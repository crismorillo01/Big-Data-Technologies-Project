"""EPSS ingestion job — daily snapshots accumulated as partitioned Parquet.

EPSS publishes one CSV snapshot per day at https://epss.empiricalsecurity.com.
Each snapshot scores every published CVE with the model's current
estimate of exploitation likelihood (``epss_score``) and where that score
ranks among all CVEs (``epss_percentile``).

We deliberately keep history: every daily run lands a new partition under
``data/silver/epss/score_date=YYYY-MM-DD/``. The Spark session is
configured with ``partitionOverwriteMode=dynamic`` so re-running the
pipeline on the same calendar day overwrites only that day's partition,
without touching older snapshots. This history is what lets the
downstream "exploitability signals" pillar of the project show how the
score for a given CVE moves over time.

Output silver schema (per partition)
------------------------------------
- ``cve_id``           : string (uppercase, trimmed)
- ``epss_score``       : double  (probability in [0, 1])
- ``epss_percentile``  : double  (in [0, 1])
- ``score_date``       : date    (partition column)
"""

from __future__ import annotations

import argparse
import logging
import shutil
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Allow plain-script execution: `spark-submit src/ingestion/ingest_epss.py`
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from pyspark.sql import DataFrame, SparkSession
from pyspark.sql.functions import col, lit, to_date, trim, upper
from pyspark.sql.types import DoubleType

from src.config import (  # noqa: E402
    RAW_EPSS_DIR,
    SILVER_EPSS_DIR,
    configure_logging,
    create_spark_session,
)
from src.utils.http import download_file, gunzip_file, url_exists  # noqa: E402


logger = logging.getLogger(__name__)

EPSS_BASE_URL = "https://epss.empiricalsecurity.com"


# ---------------------------------------------------------------------------
# Date discovery
# ---------------------------------------------------------------------------

def epss_url_for_date(date_str: str) -> str:
    """Return the EPSS daily snapshot URL for ``date_str`` (``YYYY-MM-DD``)."""
    return f"{EPSS_BASE_URL}/epss_scores-{date_str}.csv.gz"


def find_latest_available_date(max_days_back: int = 7) -> tuple[str, str]:
    """Walk back from today until we find a published EPSS snapshot.

    Returns ``(date_str, url)``. Raises ``RuntimeError`` if nothing is
    available within ``max_days_back`` days. EPSS sometimes lags by a
    day, so the default scan window is one week — enough to survive a
    weekend gap or a publication outage.
    """
    today_utc = datetime.now(tz=timezone.utc)
    for offset in range(max_days_back):
        candidate = today_utc - timedelta(days=offset)
        date_str = candidate.strftime("%Y-%m-%d")
        url = epss_url_for_date(date_str)
        if url_exists(url):
            logger.info("Latest EPSS snapshot available: %s", date_str)
            return date_str, url
    raise RuntimeError(
        f"No EPSS snapshot found within the last {max_days_back} days"
    )


def resolve_date(date_str: str | None, max_days_back: int) -> tuple[str, str]:
    """Resolve a CLI ``--date`` (or ``None``) into a concrete (date, url)."""
    if date_str:
        url = epss_url_for_date(date_str)
        if not url_exists(url):
            raise ValueError(f"EPSS snapshot not found for date: {date_str}")
        return date_str, url
    return find_latest_available_date(max_days_back)


# ---------------------------------------------------------------------------
# Spark transforms
# ---------------------------------------------------------------------------

def read_epss_csv(spark: SparkSession, csv_path: Path) -> DataFrame:
    """Read an EPSS CSV. The first line is a comment (``#model_version,...``)."""
    return (
        spark.read
        .option("header", True)
        .option("comment", "#")
        .csv(str(csv_path))
    )


def clean_epss(epss_raw: DataFrame, date_str: str) -> DataFrame:
    """Cast types, normalize column names, attach the partition column."""
    return (
        epss_raw
        .withColumnRenamed("cve", "cve_id")
        .withColumnRenamed("epss", "epss_score")
        .withColumnRenamed("percentile", "epss_percentile")
        .withColumn("cve_id", upper(trim(col("cve_id"))))
        .withColumn("epss_score", col("epss_score").cast(DoubleType()))
        .withColumn("epss_percentile", col("epss_percentile").cast(DoubleType()))
        .withColumn("score_date", to_date(lit(date_str), "yyyy-MM-dd"))
        .select("cve_id", "epss_score", "epss_percentile", "score_date")
    )


# ---------------------------------------------------------------------------
# Job entry
# ---------------------------------------------------------------------------

def run_epss_ingestion(
    spark: SparkSession,
    raw_dir: Path = RAW_EPSS_DIR,
    output_dir: Path = SILVER_EPSS_DIR,
    date_str: str | None = None,
    max_days_back: int = 7,
    force_download: bool = False,
    reset_history: bool = False,
) -> int:
    """Download a single EPSS snapshot and write it as a new partition.

    Parameters
    ----------
    date_str :
        Target date (``YYYY-MM-DD``). If ``None``, the most recent
        available snapshot is used.
    reset_history :
        If ``True``, every existing partition under ``output_dir`` is
        deleted before writing the new one. Default ``False`` (history
        accumulates). The ``partitionOverwriteMode=dynamic`` set in
        :func:`src.config.create_spark_session` ensures that a normal run
        overwrites only the matching partition.
    """
    raw_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    valid_date, url = resolve_date(date_str, max_days_back)

    gz_path = raw_dir / f"epss_scores-{valid_date}.csv.gz"
    csv_path = raw_dir / f"epss_scores-{valid_date}.csv"

    download_file(url, gz_path, force=force_download)
    gunzip_file(gz_path, csv_path, force=force_download)

    if reset_history and output_dir.exists():
        logger.warning("--reset-history: wiping %s before writing new partition", output_dir)
        shutil.rmtree(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Reading EPSS CSV for %s", valid_date)
    epss_raw = read_epss_csv(spark, csv_path)
    epss_silver = clean_epss(epss_raw, valid_date)

    epss_silver.cache()
    try:
        n_rows = epss_silver.count()
        logger.info("Writing EPSS partition score_date=%s (%d rows)", valid_date, n_rows)
        (
            epss_silver
            .coalesce(1)
            .write
            .mode("overwrite")
            .partitionBy("score_date")
            .parquet(str(output_dir))
        )
    finally:
        epss_silver.unpersist(blocking=True)

    logger.info("EPSS ingestion completed (snapshot %s, %d rows)", valid_date, n_rows)
    return n_rows


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Ingest one EPSS daily snapshot into the silver layer."
    )
    parser.add_argument("--raw-dir", type=Path, default=RAW_EPSS_DIR)
    parser.add_argument("--output-dir", type=Path, default=SILVER_EPSS_DIR)
    parser.add_argument(
        "--date",
        default=None,
        help="EPSS snapshot date (YYYY-MM-DD). Default: latest available.",
    )
    parser.add_argument(
        "--max-days-back",
        type=int,
        default=7,
        help="When --date is not given, scan back this many days. Default: 7.",
    )
    parser.add_argument(
        "--force-download",
        action="store_true",
        help="Re-download even if a local copy exists.",
    )
    parser.add_argument(
        "--reset-history",
        action="store_true",
        help="DESTRUCTIVE: wipe every existing EPSS partition before writing. "
             "Default behavior preserves all past snapshots.",
    )
    parser.add_argument(
        "--driver-memory",
        default="3g",
        help="Spark driver memory. Default: 3g.",
    )
    return parser.parse_args()


def main() -> None:
    """Entry point for ``python -m src.ingestion.ingest_epss`` and ``spark-submit``."""
    configure_logging()
    args = parse_args()

    spark = create_spark_session(
        app_name="epss-ingestion",
        driver_memory=args.driver_memory,
    )
    try:
        run_epss_ingestion(
            spark=spark,
            raw_dir=args.raw_dir,
            output_dir=args.output_dir,
            date_str=args.date,
            max_days_back=args.max_days_back,
            force_download=args.force_download,
            reset_history=args.reset_history,
        )
    finally:
        spark.stop()


if __name__ == "__main__":
    main()
