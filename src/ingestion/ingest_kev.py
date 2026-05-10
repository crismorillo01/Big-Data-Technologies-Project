"""CISA KEV ingestion job — full snapshot CSV into silver Parquet.

The Known Exploited Vulnerabilities catalog is a single CSV file
republished by CISA whenever they add new entries (typically a few times
per week, on US business hours). Volume is small (~1.5 K rows total),
but it is **the** ground-truth signal of active exploitation — every
downstream scoring step relies on it.

Output silver schema
--------------------
- ``cve_id``                          : string (uppercase, trimmed)
- ``vendor_project``                  : string
- ``product``                         : string
- ``vulnerability_name``              : string
- ``kev_date_added``                  : date (ISO 8601 from CISA)
- ``short_description``               : string
- ``required_action``                 : string
- ``known_ransomware_campaign_use``   : string ("Known" / "Unknown" / etc., raw text)
- ``is_ransomware``                   : boolean (true iff known_ransomware_campaign_use == "Known")
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

# Allow plain-script execution: `spark-submit src/ingestion/ingest_kev.py`
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from pyspark.sql import DataFrame, SparkSession
from pyspark.sql.functions import col, lower, to_date, trim, upper, when

from src.config import (  # noqa: E402
    RAW_KEV_DIR,
    RAW_KEV_FILE,
    SILVER_KEV_DIR,
    configure_logging,
    create_spark_session,
)
from src.utils.http import download_file  # noqa: E402


logger = logging.getLogger(__name__)

KEV_CSV_URL = (
    "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
)


# ---------------------------------------------------------------------------
# Spark transforms
# ---------------------------------------------------------------------------

def load_kev_raw(spark: SparkSession, raw_path: Path) -> DataFrame:
    """Read the raw KEV CSV with header inference."""
    return (
        spark.read
        .option("header", True)
        .option("inferSchema", True)
        .option("multiLine", True)        # some descriptions wrap across lines
        .option("escape", '"')
        .csv(str(raw_path))
    )


def transform_kev(kev_raw: DataFrame) -> DataFrame:
    """Normalize KEV column names and types into the silver schema."""
    return (
        kev_raw
        .withColumnRenamed("cveID", "cve_id")
        .withColumnRenamed("vendorProject", "vendor_project")
        .withColumnRenamed("vulnerabilityName", "vulnerability_name")
        .withColumnRenamed("dateAdded", "kev_date_added")
        .withColumnRenamed("shortDescription", "short_description")
        .withColumnRenamed("requiredAction", "required_action")
        .withColumnRenamed("knownRansomwareCampaignUse", "known_ransomware_campaign_use")
        .withColumn("cve_id", upper(trim(col("cve_id"))))
        .withColumn("kev_date_added", to_date(col("kev_date_added"), "yyyy-MM-dd"))
        # is_ransomware: CISA fills "Known" / "Unknown" (case-insensitive in practice).
        # Anything not exactly "Known" -> False.
        .withColumn(
            "is_ransomware",
            when(lower(trim(col("known_ransomware_campaign_use"))) == "known", True)
            .otherwise(False),
        )
        .select(
            "cve_id",
            "vendor_project",
            "product",
            "vulnerability_name",
            "kev_date_added",
            "short_description",
            "required_action",
            "known_ransomware_campaign_use",
            "is_ransomware",
        )
    )


# ---------------------------------------------------------------------------
# Job entry
# ---------------------------------------------------------------------------

def run_kev_ingestion(
    spark: SparkSession,
    raw_path: Path = RAW_KEV_FILE,
    output_dir: Path = SILVER_KEV_DIR,
    force_download: bool = False,
) -> int:
    """Run the full KEV ingestion job. Returns row count written."""
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Fetching KEV catalog")
    download_file(KEV_CSV_URL, raw_path, force=force_download)

    logger.info("Reading raw KEV CSV")
    kev_raw = load_kev_raw(spark, raw_path)

    logger.info("Normalizing KEV columns")
    kev_silver = transform_kev(kev_raw)

    kev_silver.cache()
    try:
        n_rows = kev_silver.count()
        n_distinct = kev_silver.select("cve_id").distinct().count()
        kev_silver.coalesce(1).write.mode("overwrite").parquet(str(output_dir))
    finally:
        kev_silver.unpersist(blocking=True)

    logger.info(
        "KEV ingestion completed: %d rows, %d distinct CVEs -> %s",
        n_rows, n_distinct, output_dir,
    )
    return n_rows


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description="Ingest the CISA KEV catalog.")
    parser.add_argument("--raw-path", type=Path, default=RAW_KEV_FILE)
    parser.add_argument("--output-dir", type=Path, default=SILVER_KEV_DIR)
    parser.add_argument(
        "--force-download",
        action="store_true",
        help="Re-download even if a local CSV already exists.",
    )
    parser.add_argument(
        "--driver-memory",
        default="3g",
        help="Spark driver memory. Default: 3g.",
    )
    return parser.parse_args()


def main() -> None:
    """Entry point for ``python -m src.ingestion.ingest_kev`` and ``spark-submit``."""
    configure_logging()
    args = parse_args()

    # KEV is tiny — 2g is plenty even on the smallest dev box.
    spark = create_spark_session(
        app_name="kev-ingestion",
        driver_memory=args.driver_memory,
    )
    try:
        run_kev_ingestion(
            spark=spark,
            raw_path=args.raw_path,
            output_dir=args.output_dir,
            force_download=args.force_download,
        )
    finally:
        spark.stop()


if __name__ == "__main__":
    main()
