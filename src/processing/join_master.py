"""Master dataset creation job for vulnerability intelligence.

This script reads processed datasets from the silver layer (NVD, KEV, EPSS),
joins them into a unified master dataset, and applies necessary transformations
to standardize fields across sources.

The resulting dataset consolidates vulnerability information, exploitability
signals, and known exploited flags into a single table, which is then written
to the gold layer for downstream analytics and scoring.
"""

from pyspark.sql import SparkSession
from pyspark.sql.functions import col, lit, coalesce
from pyspark.sql.types import DoubleType, IntegerType


def create_spark_session(app_name: str = "master-dataset") -> SparkSession:
    """Create Spark session."""
    spark = (
        SparkSession.builder
        .appName(app_name)
        .config("spark.driver.memory", "4g")
        .config("spark.executor.memory", "4g")
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("WARN")
    return spark


def load_datasets(spark):
    """Load silver datasets."""
    print("Loading NVD dataset...")
    nvd_df = spark.read.parquet("data/prod/silver/nvd")

    print("Loading KEV dataset...")
    kev_df = spark.read.parquet("data/prod/silver/kev")

    print("Loading EPSS dataset...")
    epss_df = spark.read.parquet("data/prod/silver/epss")

    return nvd_df, kev_df, epss_df


def prepare_kev(kev_df):
    """Create KEV flag before joining."""
    return (
        kev_df
        .select(
            "cve_id",
            "kev_date_added",
            "required_action",
            "known_ransomware_campaign_use"
        )
        .withColumn("is_kev", lit(1))
    )


def prepare_epss(epss_df):
    """Select and cast EPSS fields."""
    return (
        epss_df
        .select(
            "cve_id",
            col("epss_score").cast(DoubleType()).alias("epss_score"),
            col("epss_percentile").cast(DoubleType()).alias("epss_percentile")
        )
    )


def build_master_dataset(nvd_df, kev_df, epss_df):
    """Join NVD, KEV and EPSS into one master dataset."""
    kev_prepared = prepare_kev(kev_df)
    epss_prepared = prepare_epss(epss_df)

    print("Joining NVD + KEV + EPSS...")

    master_df = (
        nvd_df
        .join(kev_prepared, on="cve_id", how="left")
        .join(epss_prepared, on="cve_id", how="left")
        .withColumn("is_kev", coalesce(col("is_kev"), lit(0)).cast(IntegerType()))
        .withColumn("epss_score", coalesce(col("epss_score"), lit(0.0)))
        .withColumn("epss_percentile", coalesce(col("epss_percentile"), lit(0.0)))
    )

    return master_df


def save_dataset(df, output_path: str = "data/prod/gold/master_vulnerabilities"):
    """Save master dataset to the gold layer."""
    print(f"Writing master dataset to: {output_path}")

    df.write.mode("overwrite").parquet(output_path)

    print("Master dataset saved successfully.")
    print(f"Rows written: {df.count()}")


def run_master_build():
    """Run the full master dataset build job."""
    spark = create_spark_session()

    nvd_df, kev_df, epss_df = load_datasets(spark)
    master_df = build_master_dataset(nvd_df, kev_df, epss_df)

    save_dataset(master_df)

    spark.stop()


if __name__ == "__main__":
    run_master_build()
