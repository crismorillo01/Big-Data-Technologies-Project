"""NVD modified-feed ingestion with Parquet upsert into silver NVD.

Daily runs should not re-download and re-parse every yearly NVD feed.
Instead, this job downloads ``nvdcve-2.0-modified.json.gz``, transforms the
changed CVEs with the same schema as the full NVD ingestion, stores that
incremental snapshot, and updates ``data/silver/nvd/year=YYYY`` by ``cve_id``.
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

# Only keep CVEs published from this year onwards
MIN_NVD_YEAR = 2015


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


def upsert_nvd_modified(
    spark: SparkSession,
    modified_df: DataFrame,
    output_dir: Path = SILVER_NVD_DIR,
    snapshot_date: str | None = None,
) -> dict[str, int]:
    """Upsert modified NVD rows into the silver yearly partitions.

    The merge key is ``cve_id``. A CVE published in an old year but modified
    today is written back to its original ``published_year`` partition.

    Only CVEs with published_year >= MIN_NVD_YEAR are processed.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    modified_df = (
        dedupe_modified(modified_df)
        .filter(F.col("published_year") >= F.lit(MIN_NVD_YEAR))
    )

    total_modified = modified_df.count()
    if total_modified == 0:
        return {"modified_rows": 0, "affected_years": 0, "written_rows": 0}

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
        modified_ids = modified_year.select("cve_id").distinct()

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


def run_nvd_modified_ingestion(
    spark: SparkSession,
    snapshot_date: str,
    raw_dir: Path = RAW_NVD_MODIFIED_DIR,
    json_dir: Path = RAW_NVD_MODIFIED_JSON_DIR,
    updates_dir: Path = SILVER_NVD_UPDATES_DIR,
    output_dir: Path = SILVER_NVD_DIR,
    force_download: bool = True,
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

    stats = upsert_nvd_modified(
        spark,
        modified_updates,
        output_dir=output_dir,
        snapshot_date=snapshot_date,
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
    )

    try:
        run_nvd_modified_ingestion(
            spark,
            snapshot_date=args.snapshot_date,
            raw_dir=args.raw_dir,
            json_dir=args.json_dir,
            updates_dir=args.updates_dir,
            output_dir=args.output_dir,
            force_download=not args.no_force_download,
        )
    finally:
        spark.stop()


if __name__ == "__main__":
    main()
