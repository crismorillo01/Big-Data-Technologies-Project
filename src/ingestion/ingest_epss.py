"""EPSS ingestion job.

This script downloads the latest available EPSS daily snapshot, normalizes it,
and stores the cleaned dataset in the silver layer as Parquet.
"""

from __future__ import annotations

import argparse
import gzip
import os
import shutil
from datetime import datetime, timedelta
from pathlib import Path

import requests
from pyspark.sql import SparkSession, DataFrame
from pyspark.sql.functions import col, trim, upper
from pyspark.sql.types import DoubleType


EPSS_BASE_URL = "https://epss.empiricalsecurity.com"


def create_spark_session(app_name: str = "epss-ingestion") -> SparkSession:
    """Create the Spark session used by the ingestion job."""
    spark = (
        SparkSession.builder
        .appName(app_name)
        .config("spark.driver.memory", "4g")
        .config("spark.executor.memory", "4g")
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("WARN")
    return spark


def download_file(url: str, output_path: str, force_download: bool = False) -> None:
    """Download a file from a URL if it does not exist or if forced."""
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    if output.exists() and not force_download:
        print(f"File already exists. Skipping download: {output_path}")
        return

    print(f"Downloading: {url}")
    with requests.get(url, stream=True, timeout=120) as response:
        response.raise_for_status()
        with open(output_path, "wb") as file:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    file.write(chunk)


def gunzip_file(input_path: str, output_path: str, force_extract: bool = False) -> None:
    """Extract a .gz file if the output CSV does not exist or if forced."""
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    if output.exists() and not force_extract:
        print(f"CSV file already exists. Skipping extraction: {output_path}")
        return

    print(f"Extracting: {input_path}")
    with gzip.open(input_path, "rb") as file_in:
        with open(output_path, "wb") as file_out:
            shutil.copyfileobj(file_in, file_out)


def url_exists(url: str) -> bool:
    """Check if an EPSS daily snapshot URL is available."""
    try:
        response = requests.head(url, timeout=10)
        if response.status_code == 200:
            return True

        # Some servers may not support HEAD reliably, so fallback to GET.
        response = requests.get(url, stream=True, timeout=10)
        return response.status_code == 200
    except requests.RequestException:
        return False


def get_valid_epss_url(date_str: str | None = None, max_days_back: int = 7) -> tuple[str, str]:
    """Return the requested or latest available EPSS snapshot URL."""
    if date_str:
        url = f"{EPSS_BASE_URL}/epss_scores-{date_str}.csv.gz"
        if not url_exists(url):
            raise ValueError(f"EPSS file not found for date: {date_str}")
        return date_str, url

    for days_back in range(max_days_back):
        candidate_date = datetime.now() - timedelta(days=days_back)
        candidate_str = candidate_date.strftime("%Y-%m-%d")
        candidate_url = f"{EPSS_BASE_URL}/epss_scores-{candidate_str}.csv.gz"

        if url_exists(candidate_url):
            print(
                f"Latest available EPSS file found for date: {candidate_str}")
            return candidate_str, candidate_url

    raise RuntimeError(f"No EPSS file found in the last {max_days_back} days")


def read_epss_csv(spark: SparkSession, csv_path: str) -> DataFrame:
    """Read the EPSS CSV snapshot with Spark."""
    return (
        spark.read
        .option("header", True)
        .option("comment", "#")
        .csv(csv_path)
    )


def clean_epss(epss_raw: DataFrame) -> DataFrame:
    """Normalize EPSS columns and cast numeric scores."""
    return (
        epss_raw
        .withColumnRenamed("cve", "cve_id")
        .withColumnRenamed("epss", "epss_score")
        .withColumnRenamed("percentile", "epss_percentile")
        .withColumn("cve_id", upper(trim(col("cve_id"))))
        .withColumn("epss_score", col("epss_score").cast(DoubleType()))
        .withColumn("epss_percentile", col("epss_percentile").cast(DoubleType()))
        .select("cve_id", "epss_score", "epss_percentile")
    )


def run_epss_ingestion(
    spark: SparkSession,
    raw_dir: str = "data/prod/raw/epss",
    output_path: str = "data/prod/silver/epss",
    date_str: str | None = None,
    max_days_back: int = 7,
    force_download: bool = False,
) -> DataFrame:
    """Run the complete EPSS ingestion job."""
    valid_date, epss_url = get_valid_epss_url(
        date_str=date_str, max_days_back=max_days_back)

    gz_path = os.path.join(raw_dir, f"epss_scores-{valid_date}.csv.gz")
    csv_path = os.path.join(raw_dir, f"epss_scores-{valid_date}.csv")

    download_file(epss_url, gz_path, force_download=force_download)
    gunzip_file(gz_path, csv_path, force_extract=force_download)

    epss_raw = read_epss_csv(spark, csv_path)
    epss_df = clean_epss(epss_raw)

    print(f"Writing EPSS silver dataset to: {output_path}")
    epss_df.write.mode("overwrite").parquet(output_path)

    print("EPSS ingestion completed.")
    print(f"Rows written: {epss_df.count()}")
    print(f"Snapshot date: {valid_date}")

    return epss_df


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments for the EPSS ingestion job."""
    parser = argparse.ArgumentParser(
        description="Ingest EPSS daily snapshot into silver layer.")
    parser.add_argument("--raw-dir", default="data/prod/raw/epss")
    parser.add_argument("--output-path", default="data/prod/silver/epss")
    parser.add_argument("--date", default=None,
                        help="Specific EPSS date in YYYY-MM-DD format.")
    parser.add_argument("--max-days-back", type=int, default=7)
    parser.add_argument("--force-download", action="store_true")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    spark_session = create_spark_session()

    try:
        run_epss_ingestion(
            spark=spark_session,
            raw_dir=args.raw_dir,
            output_path=args.output_path,
            date_str=args.date,
            max_days_back=args.max_days_back,
            force_download=args.force_download,
        )
    finally:
        spark_session.stop()
