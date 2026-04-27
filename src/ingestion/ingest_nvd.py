"""
NVD ingestion module.

This script downloads NVD yearly JSON feeds, extracts the main CVE fields,
and stores the cleaned dataset in Parquet format.
"""

import argparse
import gzip
import os
import shutil
from typing import Iterable, List

import requests
from pyspark.sql import SparkSession, DataFrame
from pyspark.sql.functions import col, explode, expr, upper, trim


NVD_BASE_URL = "https://nvd.nist.gov/feeds/json/cve/2.0"


def create_spark_session(app_name: str = "nvd-ingestion") -> SparkSession:
    """Create the Spark session used by the ingestion job."""
    spark = (
        SparkSession.builder
        .appName(app_name)
        .config("spark.driver.memory", "6g")
        .config("spark.executor.memory", "6g")
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("WARN")
    return spark


def download_file(url: str, output_path: str, chunk_size: int = 8192) -> None:
    """Download a remote file and save it locally."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with requests.get(url, stream=True, timeout=120) as response:
        response.raise_for_status()
        with open(output_path, "wb") as file:
            for chunk in response.iter_content(chunk_size=chunk_size):
                if chunk:
                    file.write(chunk)


def gunzip_file(input_path: str, output_path: str) -> None:
    """Extract a .gz file into a regular file."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with gzip.open(input_path, "rb") as file_in:
        with open(output_path, "wb") as file_out:
            shutil.copyfileobj(file_in, file_out)


def download_nvd_years(
    years: Iterable[int],
    raw_dir: str,
    json_dir: str,
    force_download: bool = False,
) -> List[str]:
    """
    Download and extract NVD yearly feeds.

    Returns the list of extracted JSON file paths.
    """
    os.makedirs(raw_dir, exist_ok=True)
    os.makedirs(json_dir, exist_ok=True)

    extracted_paths = []

    for year in years:
        gz_url = f"{NVD_BASE_URL}/nvdcve-2.0-{year}.json.gz"
        gz_path = os.path.join(raw_dir, f"nvdcve-2.0-{year}.json.gz")
        json_path = os.path.join(json_dir, f"nvdcve-2.0-{year}.json")

        if force_download or not os.path.exists(gz_path):
            print(f"Downloading NVD feed for {year}...")
            download_file(gz_url, gz_path)
        else:
            print(
                f"NVD compressed file for {year} already exists. Skipping download.")

        if force_download or not os.path.exists(json_path):
            print(f"Extracting NVD feed for {year}...")
            gunzip_file(gz_path, json_path)
        else:
            print(
                f"NVD JSON file for {year} already exists. Skipping extraction.")

        extracted_paths.append(json_path)

    return extracted_paths


def load_nvd_raw(spark: SparkSession, json_dir: str) -> DataFrame:
    """
    Load NVD JSON files.

    NVD feeds are multi-line JSON files, so multiLine must be enabled.
    """
    return (
        spark.read
        .option("multiLine", "true")
        .json(os.path.join(json_dir, "*.json"))
    )


def transform_nvd(nvd_raw: DataFrame) -> DataFrame:
    """Extract relevant CVE fields from the nested NVD JSON structure."""
    nvd_exploded = (
        nvd_raw
        .select(explode(col("vulnerabilities")).alias("v"))
        .select("v.cve.*")
    )

    nvd_df = (
        nvd_exploded
        .select(
            upper(trim(col("id"))).alias("cve_id"),
            col("published"),
            col("lastModified"),
            expr("descriptions[0].value").alias("description"),
            expr("weaknesses[0].description[0].value").alias("cwe"),
            expr("metrics.cvssMetricV31[0].cvssData.baseScore").alias(
                "cvss_score"),
            expr("metrics.cvssMetricV31[0].cvssData.baseSeverity").alias(
                "cvss_severity"),
        )
    )

    return nvd_df


def run_nvd_ingestion(
    spark: SparkSession,
    years: Iterable[int],
    raw_dir: str = "data/prod/raw/nvd",
    json_dir: str = "data/prod/raw/nvd_json",
    output_path: str = "data/prod/silver/nvd",
    force_download: bool = False,
) -> DataFrame:
    """
    Run the full NVD ingestion process:
    download -> extract -> load -> transform -> write parquet.
    """
    download_nvd_years(
        years=years,
        raw_dir=raw_dir,
        json_dir=json_dir,
        force_download=force_download,
    )

    nvd_raw = load_nvd_raw(spark, json_dir)
    nvd_df = transform_nvd(nvd_raw)

    print(f"Writing NVD silver dataset to: {output_path}")
    nvd_df.write.mode("overwrite").parquet(output_path)

    print("NVD ingestion completed.")
    print(f"Rows written: {nvd_df.count()}")

    return nvd_df


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments for standalone execution."""
    parser = argparse.ArgumentParser(
        description="Ingest NVD vulnerability feeds.")
    parser.add_argument(
        "--years",
        nargs="+",
        type=int,
        default=[2024, 2025, 2026],
        help="NVD feed years to download and process.",
    )
    parser.add_argument(
        "--raw-dir",
        default="data/prod/raw/nvd",
        help="Directory for compressed NVD files.",
    )
    parser.add_argument(
        "--json-dir",
        default="data/prod/raw/nvd_json",
        help="Directory for extracted NVD JSON files.",
    )
    parser.add_argument(
        "--output-path",
        default="data/prod/silver/nvd",
        help="Output Parquet path for the cleaned NVD dataset.",
    )
    parser.add_argument(
        "--force-download",
        action="store_true",
        help="Force re-download and re-extraction even if files already exist.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    spark_session = create_spark_session()

    run_nvd_ingestion(
        spark=spark_session,
        years=args.years,
        raw_dir=args.raw_dir,
        json_dir=args.json_dir,
        output_path=args.output_path,
        force_download=args.force_download,
    )

    spark_session.stop()
