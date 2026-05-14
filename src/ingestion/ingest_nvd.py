"""NVD ingestion job — year-by-year processing into the silver layer.

This job downloads the NVD 2.0 yearly JSON feeds, extracts the fields
the rest of the pipeline needs, and writes one Parquet partition per
year under ``data/silver/nvd/year=YYYY/``.

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
- ``cpe_vendors``             : array<string> (deduplicated, from configurations)
- ``cpe_products``            : array<string> (deduplicated, from configurations)
- ``cpe_versions``            : array<string> (deduplicated, from CPE 2.3 version field)
- ``reference_count``         : int
- ``has_exploit_reference``   : boolean (any reference tagged "Exploit")

Partitioned by: ``year`` (= the feed year, in the path).
"""

from __future__ import annotations

import argparse
import logging
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
    SILVER_NVD_DIR,
    configure_logging,
    create_spark_session,
)
from src.utils.http import download_file, gunzip_file  # noqa: E402


logger = logging.getLogger(__name__)

NVD_BASE_URL = "https://nvd.nist.gov/feeds/json/cve/2.0"


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

# Flatten configurations[].nodes[].cpeMatch[].criteria -> array of CPE 2.3 strings.
# CPE 2.3 format: cpe:2.3:part:vendor:product:version:update:edition:lang:sw_ed:tgt_sw:tgt_hw:other
# Index 3 = vendor, 4 = product, 5 = version.
_CPE_FLAT_EXPR = (
    "flatten(transform(configurations, c ->"
    "  flatten(transform(c.nodes, n -> n.cpeMatch.criteria))"
    "))"
)


def transform_nvd_year(df_raw: DataFrame) -> DataFrame:
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
            expr(f"array_distinct(transform({_CPE_FLAT_EXPR}, cpe -> split(cpe, ':')[3]))").alias("cpe_vendors"),
            expr(f"array_distinct(transform({_CPE_FLAT_EXPR}, cpe -> split(cpe, ':')[4]))").alias("cpe_products"),
            expr(f"array_distinct(transform({_CPE_FLAT_EXPR}, cpe -> split(cpe, ':')[5]))").alias("cpe_versions"),
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


# ---------------------------------------------------------------------------
# Write
# ---------------------------------------------------------------------------

def write_year_partition(df: DataFrame, output_dir: Path, year: int) -> int:
    """Write one year as a single partition: ``data/silver/nvd/year=YYYY/``.

    Returns the row count written. Caches the DF so the count and the
    write share a single pass over the source JSON.
    """
    target = output_dir / f"year={year}"
    target.mkdir(parents=True, exist_ok=True)

    df.cache()
    try:
        n_rows = df.count()
        # Coalesce to a single file: a typical year is 30-60 K rows of small
        # records, well below any sensible Parquet split point.
        df.coalesce(1).write.mode("overwrite").parquet(str(target))
    finally:
        df.unpersist(blocking=True)

    return n_rows


# ---------------------------------------------------------------------------
# Job entry
# ---------------------------------------------------------------------------

def run_nvd_ingestion(
    spark: SparkSession,
    years: Iterable[int],
    raw_dir: Path = RAW_NVD_DIR,
    json_dir: Path = RAW_NVD_JSON_DIR,
    output_dir: Path = SILVER_NVD_DIR,
    force_download: bool = False,
) -> int:
    """Run the year-by-year NVD ingestion. Returns total rows written."""
    raw_dir.mkdir(parents=True, exist_ok=True)
    json_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    years_list = list(years)
    logger.info("NVD ingestion starting for years: %s", years_list)

    total_rows = 0
    for year in years_list:
        logger.info("[year %d] downloading + extracting", year)
        json_path = fetch_nvd_year(year, raw_dir, json_dir, force=force_download)

        logger.info("[year %d] reading and transforming", year)
        df_raw = load_nvd_year(spark, json_path)
        df_silver = transform_nvd_year(df_raw)

        logger.info("[year %d] writing silver partition", year)
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
    )
    try:
        run_nvd_ingestion(
            spark=spark,
            years=args.years,
            raw_dir=args.raw_dir,
            json_dir=args.json_dir,
            output_dir=args.output_dir,
            force_download=args.force_download,
        )
    finally:
        spark.stop()


if __name__ == "__main__":
    main()
