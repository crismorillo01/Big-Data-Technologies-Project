"""NVD modified-feed ingestion with Delta upsert into silver NVD.

Daily runs should not re-download and re-parse every yearly NVD feed.
Instead, this job downloads ``nvdcve-2.0-modified.json.gz``, transforms the
changed CVEs with the same schema as the full NVD ingestion, stores that
incremental snapshot in Parquet for lineage, and upserts the canonical
``data/silver/nvd_delta`` table by ``cve_id``. A legacy Parquet-only
upsert is still available with ``--nvd-storage parquet``.
"""

from __future__ import annotations

import argparse
import logging
import shutil
import sys
from pathlib import Path

from pyspark.sql import DataFrame, SparkSession
from pyspark.sql import functions as F
from pyspark.sql.window import Window

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.config import (  # noqa: E402
    RAW_NVD_MODIFIED_DIR,
    RAW_NVD_MODIFIED_JSON_DIR,
    SILVER_NVD_DELTA_DIR,
    SILVER_NVD_DIR,
    SILVER_NVD_UPDATES_DIR,
    configure_logging,
    create_spark_session,
    get_snapshot_date,
)
from src.ingestion.ingest_nvd import load_nvd_year, transform_nvd_year  # noqa: E402
from src.utils.http import download_file, gunzip_file  # noqa: E402


logger = logging.getLogger(__name__)

NVD_MODIFIED_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz"
NVD_STORAGE_PARQUET = "parquet"
NVD_STORAGE_DELTA = "delta"


def fetch_nvd_modified(
    snapshot_date: str,
    raw_dir: Path = RAW_NVD_MODIFIED_DIR,
    json_dir: Path = RAW_NVD_MODIFIED_JSON_DIR,
    force: bool = False,
) -> Path:
    """Download and extract the NVD modified feed for one pipeline snapshot."""
    raw_partition = raw_dir / f"snapshot_date={snapshot_date}"
    json_partition = json_dir / f"snapshot_date={snapshot_date}"
    gz_path = raw_partition / "nvdcve-2.0-modified.json.gz"
    json_path = json_partition / "nvdcve-2.0-modified.json"

    download_file(NVD_MODIFIED_URL, gz_path, force=force)
    gunzip_file(gz_path, json_path, force=force)
    return json_path


def dedupe_modified(df: DataFrame) -> DataFrame:
    """Keep the latest row per CVE from the modified feed."""
    w = Window.partitionBy("cve_id").orderBy(
        F.col("last_modified").desc_nulls_last())
    return (
        df.filter(F.col("cve_id").isNotNull())
        .withColumn("_rn", F.row_number().over(w))
        .filter(F.col("_rn") == 1)
        .drop("_rn")
    )


def write_modified_updates(df: DataFrame, updates_dir: Path, snapshot_date: str) -> Path:
    """Persist the modified rows for lineage and to avoid re-reading JSON."""
    target = updates_dir / f"snapshot_date={snapshot_date}"
    target.mkdir(parents=True, exist_ok=True)
    df.write.mode("overwrite").parquet(str(target))
    return target


def _empty_like(spark: SparkSession, df: DataFrame) -> DataFrame:
    return spark.createDataFrame([], df.schema)


def _replace_directory(tmp_target: Path, final_target: Path) -> None:
    """Replace a partition directory after a successful write to temp."""
    if final_target.exists():
        shutil.rmtree(final_target)
    tmp_target.replace(final_target)


def _delta_table_exists(delta_dir: Path) -> bool:
    return (delta_dir / "_delta_log").exists()


def _load_delta_table(delta_dir: Path):
    try:
        from delta.tables import DeltaTable
    except ImportError as exc:
        raise RuntimeError(
            "Delta Lake support requires delta-spark. Install project requirements first."
        ) from exc

    return DeltaTable.forPath


def bootstrap_nvd_delta_from_parquet(
    spark: SparkSession,
    parquet_dir: Path = SILVER_NVD_DIR,
    delta_dir: Path = SILVER_NVD_DELTA_DIR,
    min_year: int = 2015,
) -> int:
    """Create the Delta silver table once from an existing legacy Parquet base."""
    if not parquet_dir.exists() or not any(parquet_dir.rglob("*.parquet")):
        raise FileNotFoundError(
            f"Cannot bootstrap Delta NVD because no Parquet base exists at {parquet_dir}"
        )

    delta_dir.parent.mkdir(parents=True, exist_ok=True)
    tmp_delta = delta_dir.parent / f"_tmp_{delta_dir.name}"

    if tmp_delta.exists():
        shutil.rmtree(tmp_delta)

    df = (
        spark.read.parquet(str(parquet_dir))
        .drop("year")
        .filter(F.col("published_year") >= F.lit(min_year))
    )
    n_rows = df.count()

    (
        df.write
        .format("delta")
        .mode("overwrite")
        .partitionBy("published_year")
        .save(str(tmp_delta))
    )

    _replace_directory(tmp_delta, delta_dir)
    logger.info("Bootstrapped Delta NVD table at %s with %d rows", delta_dir, n_rows)
    return int(n_rows)


def upsert_nvd_modified(
    spark: SparkSession,
    modified_df: DataFrame,
    output_dir: Path = SILVER_NVD_DIR,
    snapshot_date: str | None = None,
    min_year: int = 2015,
) -> dict[str, int]:
    """Upsert modified NVD rows into the silver yearly partitions.

    The merge key is ``cve_id``. A CVE published in an old year but modified
    today is written back to its original ``published_year`` partition.

    Only CVEs with published_year >= min_year are processed.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    modified_df = (
        dedupe_modified(modified_df)
        .filter(F.col("published_year") >= F.lit(min_year))
    )

    total_modified = modified_df.count()
    if total_modified == 0:
        return {"modified_rows": 0, "affected_years": 0, "written_rows": 0}

    modified_years = [
        int(row["published_year"])
        for row in (
            modified_df
            .filter(F.col("published_year").isNotNull())
            .select("published_year")
            .distinct()
            .collect()
        )
    ]
    modified_ids = modified_df.select("cve_id").distinct()

    existing_years: list[int] = []
    if output_dir.exists() and any(output_dir.rglob("*.parquet")):
        existing_all = spark.read.parquet(str(output_dir))
        if "year" in existing_all.columns:
            existing_years = [
                int(row["year"])
                for row in (
                    existing_all
                    .join(modified_ids, on="cve_id", how="inner")
                    .filter(F.col("year").isNotNull())
                    .select("year")
                    .distinct()
                    .collect()
                )
            ]

    affected_years = sorted(set(modified_years) | set(existing_years))

    written_rows = 0
    suffix = snapshot_date or "latest"

    for year in affected_years:
        target = output_dir / f"year={year}"
        tmp_target = output_dir / \
            f"_tmp_modified_year={year}_snapshot={suffix}"

        if tmp_target.exists():
            shutil.rmtree(tmp_target)

        modified_year = modified_df.filter(
            F.col("published_year") == F.lit(year))

        if target.exists() and any(target.glob("*.parquet")):
            existing_year = spark.read.parquet(str(target))
        else:
            existing_year = _empty_like(spark, modified_df)

        updated_year = (
            existing_year
            .join(modified_ids, on="cve_id", how="left_anti")
            .unionByName(modified_year, allowMissingColumns=True)
        )

        updated_year.write.mode("overwrite").parquet(str(tmp_target))
        year_rows = spark.read.parquet(str(tmp_target)).count()

        _replace_directory(tmp_target, target)

        written_rows += year_rows

        logger.info(
            "[year %d] upserted modified CVEs; partition now has %d rows",
            year,
            year_rows,
        )

    return {
        "modified_rows": int(total_modified),
        "affected_years": len(affected_years),
        "written_rows": int(written_rows),
    }


def upsert_nvd_modified_delta(
    spark: SparkSession,
    modified_df: DataFrame,
    delta_dir: Path = SILVER_NVD_DELTA_DIR,
    bootstrap_parquet_dir: Path = SILVER_NVD_DIR,
    snapshot_date: str | None = None,
    min_year: int = 2015,
) -> dict[str, int]:
    """Upsert modified NVD rows into the Delta silver table."""
    modified_df = (
        dedupe_modified(modified_df)
        .drop("year")
        .filter(F.col("published_year") >= F.lit(min_year))
    )

    total_modified = modified_df.count()
    if total_modified == 0:
        return {"modified_rows": 0, "affected_years": 0, "written_rows": 0}

    if not _delta_table_exists(delta_dir):
        bootstrap_nvd_delta_from_parquet(
            spark,
            parquet_dir=bootstrap_parquet_dir,
            delta_dir=delta_dir,
            min_year=min_year,
        )

    delta_table_for_path = _load_delta_table(delta_dir)
    delta_table = delta_table_for_path(spark, str(delta_dir))

    affected_years = [
        int(row["published_year"])
        for row in (
            modified_df
            .filter(F.col("published_year").isNotNull())
            .select("published_year")
            .distinct()
            .collect()
        )
    ]

    (
        delta_table.alias("target")
        .merge(
            modified_df.alias("source"),
            "target.cve_id = source.cve_id",
        )
        .whenMatchedUpdateAll()
        .whenNotMatchedInsertAll()
        .execute()
    )

    written_rows = (
        spark.read.format("delta").load(str(delta_dir))
        .filter(F.col("published_year") >= F.lit(min_year))
        .count()
    )

    return {
        "modified_rows": int(total_modified),
        "affected_years": len(set(affected_years)),
        "written_rows": int(written_rows),
    }


def run_nvd_modified_ingestion(
    spark: SparkSession,
    snapshot_date: str,
    raw_dir: Path = RAW_NVD_MODIFIED_DIR,
    json_dir: Path = RAW_NVD_MODIFIED_JSON_DIR,
    updates_dir: Path = SILVER_NVD_UPDATES_DIR,
    output_dir: Path = SILVER_NVD_DIR,
    delta_output_dir: Path = SILVER_NVD_DELTA_DIR,
    nvd_storage: str = NVD_STORAGE_DELTA,
    force_download: bool = True,
    min_year: int = 2015,
) -> dict[str, int]:
    """Download, store and upsert the NVD modified feed."""
    logger.info(
        "NVD modified ingestion starting for snapshot_date=%s", snapshot_date)

    json_path = fetch_nvd_modified(
        snapshot_date,
        raw_dir,
        json_dir,
        force=force_download,
    )

    df_raw = load_nvd_year(spark, json_path)

    df_modified = dedupe_modified(transform_nvd_year(df_raw, year=0))

    updates_path = write_modified_updates(
        df_modified,
        updates_dir,
        snapshot_date,
    )

    modified_updates = spark.read.parquet(str(updates_path))

    if nvd_storage == NVD_STORAGE_DELTA:
        stats = upsert_nvd_modified_delta(
            spark,
            modified_updates,
            delta_dir=delta_output_dir,
            bootstrap_parquet_dir=output_dir,
            snapshot_date=snapshot_date,
            min_year=min_year,
        )
    else:
        stats = upsert_nvd_modified(
            spark,
            modified_updates,
            output_dir=output_dir,
            snapshot_date=snapshot_date,
            min_year=min_year,
        )

    logger.info(
        "NVD modified ingestion complete: modified_rows=%d affected_years=%d written_rows=%d",
        stats["modified_rows"],
        stats["affected_years"],
        stats["written_rows"],
    )

    return stats


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Ingest the NVD modified feed into silver NVD."
    )

    parser.add_argument(
        "--snapshot-date",
        default=get_snapshot_date(),
        help="Pipeline snapshot date (YYYY-MM-DD). Default: today UTC.",
    )

    parser.add_argument("--raw-dir", type=Path, default=RAW_NVD_MODIFIED_DIR)
    parser.add_argument("--json-dir", type=Path,
                        default=RAW_NVD_MODIFIED_JSON_DIR)
    parser.add_argument("--updates-dir", type=Path,
                        default=SILVER_NVD_UPDATES_DIR)
    parser.add_argument("--output-dir", type=Path, default=SILVER_NVD_DIR)
    parser.add_argument("--delta-output-dir", type=Path,
                        default=SILVER_NVD_DELTA_DIR)
    parser.add_argument(
        "--nvd-storage",
        choices=[NVD_STORAGE_PARQUET, NVD_STORAGE_DELTA],
        default=NVD_STORAGE_DELTA,
        help="Silver NVD storage engine. Default: delta. Use parquet for legacy Parquet-only mode.",
    )
    parser.add_argument(
        "--min-year",
        type=int,
        default=2015,
        help="Ignore modified CVEs published before this year. Default: 2015.",
    )

    parser.add_argument(
        "--no-force-download",
        action="store_true",
        help="Reuse the local modified feed for this snapshot if it already exists.",
    )

    parser.add_argument(
        "--driver-memory",
        default="3g",
        help="Spark driver memory. Default: 3g.",
    )

    return parser.parse_args()


def main() -> None:
    configure_logging()

    args = parse_args()

    spark = create_spark_session(
        "nvd-modified-ingestion",
        driver_memory=args.driver_memory,
        enable_delta=args.nvd_storage == NVD_STORAGE_DELTA,
    )

    try:
        run_nvd_modified_ingestion(
            spark,
            snapshot_date=args.snapshot_date,
            raw_dir=args.raw_dir,
            json_dir=args.json_dir,
            updates_dir=args.updates_dir,
            output_dir=args.output_dir,
            delta_output_dir=args.delta_output_dir,
            nvd_storage=args.nvd_storage,
            force_download=not args.no_force_download,
            min_year=args.min_year,
        )
    finally:
        spark.stop()


if __name__ == "__main__":
    main()
