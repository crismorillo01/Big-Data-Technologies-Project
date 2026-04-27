"""
CISA KEV ingestion module.

This script downloads the Known Exploited Vulnerabilities catalog,
normalizes its schema, and stores the cleaned dataset in Parquet format.
"""

import argparse
import os

import requests
from pyspark.sql import DataFrame, SparkSession
from pyspark.sql.functions import col, trim, upper


KEV_CSV_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"


def create_spark_session(app_name: str = "kev-ingestion") -> SparkSession:
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


def download_file(url: str, output_path: str, chunk_size: int = 8192) -> None:
    """Download a remote file and save it locally."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with requests.get(url, stream=True, timeout=120) as response:
        response.raise_for_status()
        with open(output_path, "wb") as file:
            for chunk in response.iter_content(chunk_size=chunk_size):
                if chunk:
                    file.write(chunk)


def download_kev_catalog(raw_path: str, force_download: bool = True) -> str:
    """
    Download the latest KEV CSV catalog.

    KEV is published as a full snapshot, so overwriting the local file is fine.
    """
    if force_download or not os.path.exists(raw_path):
        print("Downloading CISA KEV catalog...")
        download_file(KEV_CSV_URL, raw_path)
    else:
        print("KEV raw file already exists. Skipping download.")

    return raw_path


def load_kev_raw(spark: SparkSession, raw_path: str) -> DataFrame:
    """Load the raw KEV CSV file with Spark."""
    return (
        spark.read
        .option("header", True)
        .option("inferSchema", True)
        .csv(raw_path)
    )


def transform_kev(kev_raw: DataFrame) -> DataFrame:
    """Normalize KEV column names and keep the fields used downstream."""
    kev_df = (
        kev_raw
        .withColumnRenamed("cveID", "cve_id")
        .withColumnRenamed("vendorProject", "vendor_project")
        .withColumnRenamed("vulnerabilityName", "vulnerability_name")
        .withColumnRenamed("dateAdded", "kev_date_added")
        .withColumnRenamed("shortDescription", "short_description")
        .withColumnRenamed("requiredAction", "required_action")
        .withColumnRenamed("knownRansomwareCampaignUse", "known_ransomware_campaign_use")
        .withColumn("cve_id", upper(trim(col("cve_id"))))
    )

    return kev_df.select(
        "cve_id",
        "vendor_project",
        "product",
        "vulnerability_name",
        "kev_date_added",
        "short_description",
        "required_action",
        "known_ransomware_campaign_use",
    )


def run_kev_ingestion(
    spark: SparkSession,
    raw_path: str = "data/prod/raw/kev/known_exploited_vulnerabilities.csv",
    output_path: str = "data/prod/silver/kev",
    force_download: bool = True,
) -> DataFrame:
    """
    Run the full KEV ingestion process:
    download -> load -> transform -> write parquet.
    """
    download_kev_catalog(raw_path=raw_path, force_download=force_download)

    kev_raw = load_kev_raw(spark, raw_path)
    kev_df = transform_kev(kev_raw)

    print(f"Writing KEV silver dataset to: {output_path}")
    kev_df.write.mode("overwrite").parquet(output_path)

    print("KEV ingestion completed.")
    print(f"Rows written: {kev_df.count()}")
    print(f"Distinct CVEs: {kev_df.select('cve_id').distinct().count()}")

    return kev_df


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments for standalone execution."""
    parser = argparse.ArgumentParser(description="Ingest CISA KEV catalog.")
    parser.add_argument(
        "--raw-path",
        default="data/prod/raw/kev/known_exploited_vulnerabilities.csv",
        help="Local path for the downloaded KEV CSV file.",
    )
    parser.add_argument(
        "--output-path",
        default="data/prod/silver/kev",
        help="Output Parquet path for the cleaned KEV dataset.",
    )
    parser.add_argument(
        "--skip-download",
        action="store_true",
        help="Use the existing local CSV file instead of downloading it again.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    spark_session = create_spark_session()

    run_kev_ingestion(
        spark=spark_session,
        raw_path=args.raw_path,
        output_path=args.output_path,
        force_download=not args.skip_download,
    )

    spark_session.stop()
