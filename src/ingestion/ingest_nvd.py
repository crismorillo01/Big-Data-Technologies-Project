"""NVD ingestion job — year-by-year processing into the silver layer.

This job downloads the NVD 2.0 yearly JSON feeds, extracts the fields
the rest of the pipeline needs, and writes the canonical NVD silver
table to Delta Lake under ``data/silver/nvd_delta`` by default. A
legacy Parquet-only mode is still available with ``--nvd-storage parquet``.

Why year-by-year
----------------
Each yearly NVD feed is ~150-200 MB JSON (multi-line, deeply nested).
On an 8 GB RAM laptop, loading the full 12-year window at once and then
exploding ``vulnerabilities`` into ~300 K rows of nested structs is on
the edge of memory comfort. Processing one year per Spark action keeps
the working set small, lets us write each year as a clean partition,
and makes incremental re-runs trivial: bump the year, re-run, only that
partition is rewritten.

Output silver schema
--------------------
- ``cve_id``                  : string (uppercase, trimmed)
- ``published``               : timestamp
- ``last_modified``           : timestamp
- ``published_year``          : int (year(published); equal to the feed year for most CVEs)
- ``description``             : string (English description, primary)
- ``cwes``                    : array<string> (all CWE-XXX values across all weaknesses, deduplicated)
- ``cvss_score``              : double (fallback v4 → v3.1 → v3.0 → v2)
- ``cvss_severity``           : string (matched fallback path)
- ``cvss_version``            : string ("v4.0" | "v3.1" | "v3.0" | "v2" | null)
- ``cpe_vendors``             : array<string> (deduplicated, capped from configurations)
- ``cpe_products``            : array<string> (deduplicated, capped from configurations)
- ``cpe_versions``            : array<string> (deduplicated, capped from CPE 2.3 version field)
- ``reference_count``         : int
- ``has_exploit_reference``   : boolean (any reference tagged "Exploit")

Delta partitioned by: ``published_year``.
Legacy Parquet partitioned by: ``year`` (= the feed year, in the path).
"""

from __future__ import annotations

import argparse
import logging
import shutil
import sys
from pathlib import Path
from typing import Iterable

# Allow plain-script execution: `spark-submit src/ingestion/ingest_nvd.py`
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from pyspark.sql import DataFrame, SparkSession
from pyspark.sql.functions import (
    coalesce,
    col,
    explode,
    expr,
    lit,
    size,
    to_timestamp,
    trim,
    upper,
    when,
    year as spark_year,
)

from src.config import (  # noqa: E402  (after sys.path tweak)
    DEFAULT_NVD_YEARS,
    RAW_NVD_DIR,
    RAW_NVD_JSON_DIR,
    SILVER_NVD_DELTA_DIR,
    SILVER_NVD_DIR,
    configure_logging,
    create_spark_session,
)
from src.utils.http import download_file, gunzip_file  # noqa: E402


logger = logging.getLogger(__name__)

NVD_BASE_URL = "https://nvd.nist.gov/feeds/json/cve/2.0"
NVD_STORAGE_PARQUET = "parquet"
NVD_STORAGE_DELTA = "delta"


# ---------------------------------------------------------------------------
# Download / extract
# ---------------------------------------------------------------------------

def nvd_url_for_year(year: int) -> str:
    """Return the NVD 2.0 yearly feed URL for ``year``."""
    return f"{NVD_BASE_URL}/nvdcve-2.0-{year}.json.gz"


def fetch_nvd_year(
    year: int,
    raw_dir: Path,
    json_dir: Path,
    force: bool = False,
) -> Path:
    """Download and extract one NVD year. Returns the extracted JSON path."""
    gz_path = raw_dir / f"nvdcve-2.0-{year}.json.gz"
    json_path = json_dir / f"nvdcve-2.0-{year}.json"

    download_file(nvd_url_for_year(year), gz_path, force=force)
    gunzip_file(gz_path, json_path, force=force)
    return json_path


# ---------------------------------------------------------------------------
# Spark transforms
# ---------------------------------------------------------------------------

def load_nvd_year(spark: SparkSession, json_path: Path) -> DataFrame:
    """Read a single NVD yearly JSON file (multi-line)."""
    return (
        spark.read
        .option("multiLine", "true")
        .json(str(json_path))
    )


# CVSS extraction expressions, written once and reused inside transform_nvd_year.
# NOTE: V2 stores baseSeverity at the metric level, NOT inside cvssData (V3+ moved it).
_CVSS_SCORE_EXPR = (
    "coalesce("
    " metrics.cvssMetricV40[0].cvssData.baseScore,"
    " metrics.cvssMetricV31[0].cvssData.baseScore,"
    " metrics.cvssMetricV30[0].cvssData.baseScore,"
    " metrics.cvssMetricV2[0].cvssData.baseScore"
    ")"
)
_CVSS_SEVERITY_EXPR = (
    "coalesce("
    " metrics.cvssMetricV40[0].cvssData.baseSeverity,"
    " metrics.cvssMetricV31[0].cvssData.baseSeverity,"
    " metrics.cvssMetricV30[0].cvssData.baseSeverity,"
    " metrics.cvssMetricV2[0].baseSeverity"  # <- v2 quirk: not under cvssData
    ")"
)

# Flatten weaknesses[].description[].value -> array of CWE strings, dedup, drop nulls
# and non-CWE markers like "NVD-CWE-Other" / "NVD-CWE-noinfo".
_CWES_EXPR = (
    "filter("
    " array_distinct(flatten(transform(weaknesses, w -> transform(w.description, d -> d.value)))),"
    " cwe -> cwe is not null and cwe like 'CWE-%'"
    ")"
)

# Flatten a bounded slice of configurations[].nodes[].cpeMatch[].criteria.
#
# Some NVD records contain extremely large CPE match lists. Keeping every CPE
# in a single row can exceed the local JVM heap while Spark writes Parquet.
# Downstream jobs only need representative vendors/products, so cap the nested
# lists before flattening instead of building a huge intermediate array.
# CPE 2.3 format: cpe:2.3:part:vendor:product:version:update:edition:lang:sw_ed:tgt_sw:tgt_hw:other
# Index 3 = vendor, 4 = product, 5 = version.
_CPE_FLAT_EXPR = (
    "flatten(transform(slice(configurations, 1, 20), c ->"
    "  flatten(transform(slice(c.nodes, 1, 20), n ->"
    "    transform(slice(n.cpeMatch, 1, 200), m -> m.criteria)"
    "  ))"
    "))"
)
_CPE_ARRAY_LIMIT = 500


def transform_nvd_year(df_raw: DataFrame, year: int) -> DataFrame:
    """Project the raw NVD year DataFrame onto the silver schema."""
    exploded = (
        df_raw
        .select(explode(col("vulnerabilities")).alias("v"))
        .select("v.cve.*")
    )

    silver = (
        exploded
        .select(
            upper(trim(col("id"))).alias("cve_id"),
            to_timestamp(col("published")).alias("published"),
            to_timestamp(col("lastModified")).alias("last_modified"),
            expr("descriptions[0].value").alias("description"),
            expr(_CWES_EXPR).alias("cwes"),
            expr(_CVSS_SCORE_EXPR).cast("double").alias("cvss_score"),
            expr(_CVSS_SEVERITY_EXPR).alias("cvss_severity"),
            (
                when(expr("metrics.cvssMetricV40[0].cvssData.baseScore is not null"), lit("v4.0"))
                .when(expr("metrics.cvssMetricV31[0].cvssData.baseScore is not null"), lit("v3.1"))
                .when(expr("metrics.cvssMetricV30[0].cvssData.baseScore is not null"), lit("v3.0"))
                .when(expr("metrics.cvssMetricV2[0].cvssData.baseScore is not null"), lit("v2"))
                .otherwise(lit(None).cast("string"))
                .alias("cvss_version")
            ),
            expr(
                "slice("
                f"array_distinct(transform({_CPE_FLAT_EXPR}, cpe -> split(cpe, ':')[3])),"
                f" 1, {_CPE_ARRAY_LIMIT})"
            ).alias("cpe_vendors"),
            expr(
                "slice("
                f"array_distinct(transform({_CPE_FLAT_EXPR}, cpe -> split(cpe, ':')[4])),"
                f" 1, {_CPE_ARRAY_LIMIT})"
            ).alias("cpe_products"),
            expr(
                "slice("
                f"array_distinct(transform({_CPE_FLAT_EXPR}, cpe -> split(cpe, ':')[5])),"
                f" 1, {_CPE_ARRAY_LIMIT})"
            ).alias("cpe_versions"),
            (
                when(col("references").isNull(), lit(0))
                .otherwise(size(col("references")))
                .alias("reference_count")
            ),
            coalesce(
                expr("exists(references, r -> array_contains(r.tags, 'Exploit'))"),
                lit(False),
            ).alias("has_exploit_reference"),
        )
        .withColumn("published_year", spark_year(col("published")))
    )

    return silver


def filter_min_published_year(df: DataFrame, min_year: int) -> DataFrame:
    """Keep only CVEs published within the configured NVD analysis window."""
    return df.filter(col("published_year") >= lit(min_year))


# ---------------------------------------------------------------------------
# Write
# ---------------------------------------------------------------------------

def write_year_partition(df: DataFrame, output_dir: Path, year: int) -> int:
    """Write one year under ``data/silver/nvd/year=YYYY/``.

    Returns the row count written. The DataFrame is intentionally not cached:
    full NVD years contain wide nested fields and can exceed local JVM heap
    when stored in Spark's in-memory cache.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    target = output_dir / f"year={year}"
    tmp_target = output_dir / f"_tmp_year={year}"
    if tmp_target.exists():
        shutil.rmtree(tmp_target)

    df.write.mode("overwrite").parquet(str(tmp_target))
    n_rows = df.sparkSession.read.parquet(str(tmp_target)).count()

    if target.exists():
        shutil.rmtree(target)
    tmp_target.replace(target)
    return n_rows


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


def write_year_delta(
    df: DataFrame,
    delta_dir: Path,
    year: int,
    replace_delta_table: bool = False,
) -> int:
    """Write one full NVD year into the experimental Delta silver table."""
    delta_dir.parent.mkdir(parents=True, exist_ok=True)
    df_delta = df.drop("year")
    n_rows = df_delta.count()

    if replace_delta_table and delta_dir.exists():
        shutil.rmtree(delta_dir)

    if not _delta_table_exists(delta_dir):
        (
            df_delta.write
            .format("delta")
            .mode("overwrite")
            .partitionBy("published_year")
            .save(str(delta_dir))
        )
        return int(n_rows)

    delta_table_for_path = _load_delta_table(delta_dir)
    delta_table = delta_table_for_path(df.sparkSession, str(delta_dir))

    (
        delta_table.alias("target")
        .merge(
            df_delta.alias("source"),
            "target.cve_id = source.cve_id",
        )
        .whenMatchedUpdateAll()
        .whenNotMatchedInsertAll()
        .execute()
    )

    logger.info("[year %d] merged %d rows into Delta NVD table", year, n_rows)
    return int(n_rows)


# ---------------------------------------------------------------------------
# Job entry
# ---------------------------------------------------------------------------

def run_nvd_ingestion(
    spark: SparkSession,
    years: Iterable[int],
    raw_dir: Path = RAW_NVD_DIR,
    json_dir: Path = RAW_NVD_JSON_DIR,
    output_dir: Path = SILVER_NVD_DIR,
    delta_output_dir: Path = SILVER_NVD_DELTA_DIR,
    nvd_storage: str = NVD_STORAGE_DELTA,
    replace_delta_table: bool = False,
    min_year: int = min(DEFAULT_NVD_YEARS),
    force_download: bool = False,
) -> int:
    """Run the year-by-year NVD ingestion. Returns total rows written."""
    raw_dir.mkdir(parents=True, exist_ok=True)
    json_dir.mkdir(parents=True, exist_ok=True)
    if nvd_storage == NVD_STORAGE_DELTA:
        delta_output_dir.parent.mkdir(parents=True, exist_ok=True)
    else:
        output_dir.mkdir(parents=True, exist_ok=True)

    years_list = list(years)
    logger.info("NVD ingestion starting for years: %s", years_list)
    logger.info("NVD silver storage mode: %s", nvd_storage)
    logger.info("NVD minimum published year: %d", min_year)

    total_rows = 0
    for year in years_list:
        logger.info("[year %d] downloading + extracting", year)
        json_path = fetch_nvd_year(year, raw_dir, json_dir, force=force_download)

        logger.info("[year %d] reading and transforming", year)
        df_raw = load_nvd_year(spark, json_path)
        df_silver = filter_min_published_year(
            transform_nvd_year(df_raw, year),
            min_year,
        )

        logger.info("[year %d] writing silver partition", year)
        if nvd_storage == NVD_STORAGE_DELTA:
            n_rows = write_year_delta(
                df_silver,
                delta_output_dir,
                year,
                replace_delta_table=replace_delta_table and year == years_list[0],
            )
        else:
            n_rows = write_year_partition(df_silver, output_dir, year)
        total_rows += n_rows
        logger.info("[year %d] done (%d rows)", year, n_rows)

    logger.info("NVD ingestion completed: %d rows across %d year(s)",
                total_rows, len(years_list))
    return total_rows


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Ingest NVD vulnerability feeds (year-by-year)."
    )
    parser.add_argument(
        "--years",
        nargs="+",
        type=int,
        default=DEFAULT_NVD_YEARS,
        help=f"NVD feed years to process. Default: {DEFAULT_NVD_YEARS}",
    )
    parser.add_argument("--raw-dir", type=Path, default=RAW_NVD_DIR)
    parser.add_argument("--json-dir", type=Path, default=RAW_NVD_JSON_DIR)
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
        "--replace-delta-table",
        action="store_true",
        help="Drop and recreate the Delta NVD table before writing the first requested year.",
    )
    parser.add_argument(
        "--min-year",
        type=int,
        default=min(DEFAULT_NVD_YEARS),
        help="Keep only CVEs published from this year onward. Default: 2015.",
    )
    parser.add_argument(
        "--force-download",
        action="store_true",
        help="Re-download and re-extract even if local files already exist.",
    )
    parser.add_argument(
        "--driver-memory",
        default="3g",
        help="Spark driver memory. Default: 3g (tuned for 8 GB RAM).",
    )
    return parser.parse_args()


def main() -> None:
    """Entry point for ``python -m src.ingestion.ingest_nvd`` and ``spark-submit``."""
    configure_logging()
    args = parse_args()

    spark = create_spark_session(
        app_name="nvd-ingestion",
        driver_memory=args.driver_memory,
        enable_delta=args.nvd_storage == NVD_STORAGE_DELTA,
    )
    try:
        run_nvd_ingestion(
            spark=spark,
            years=args.years,
            raw_dir=args.raw_dir,
            json_dir=args.json_dir,
            output_dir=args.output_dir,
            delta_output_dir=args.delta_output_dir,
            nvd_storage=args.nvd_storage,
            replace_delta_table=args.replace_delta_table,
            min_year=args.min_year,
            force_download=args.force_download,
        )
    finally:
        spark.stop()


if __name__ == "__main__":
    main()
