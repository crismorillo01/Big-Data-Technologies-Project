"""Priority scoring job for vulnerability remediation.

This script reads the master vulnerability dataset from the gold layer,
computes an interpretable priority score, assigns priority levels, and
writes the scored dataset back to the gold layer.
"""

from __future__ import annotations

import argparse

from pyspark.sql import DataFrame, SparkSession
from pyspark.sql.functions import col, coalesce, lit, round as spark_round, when
from pyspark.sql.types import DoubleType, IntegerType


DEFAULT_INPUT_PATH = "data/prod/gold/master_vulnerabilities"
DEFAULT_OUTPUT_PATH = "data/prod/gold/vulnerability_scores"


def create_spark_session(app_name: str = "priority-scoring") -> SparkSession:
    """Create the Spark session used by the scoring job."""
    spark = (
        SparkSession.builder
        .appName(app_name)
        .config("spark.driver.memory", "4g")
        .config("spark.executor.memory", "4g")
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("WARN")
    return spark


def load_master_dataset(spark: SparkSession, input_path: str) -> DataFrame:
    """Load the master vulnerability dataset."""
    print(f"Loading master dataset from: {input_path}")
    return spark.read.parquet(input_path)


def prepare_scoring_columns(df: DataFrame) -> DataFrame:
    """Cast and fill the columns needed for scoring."""
    return (
        df
        .withColumn("cvss_score", coalesce(col("cvss_score").cast(DoubleType()), lit(0.0)))
        .withColumn("epss_score", coalesce(col("epss_score").cast(DoubleType()), lit(0.0)))
        .withColumn("epss_percentile", coalesce(col("epss_percentile").cast(DoubleType()), lit(0.0)))
        .withColumn("is_kev", coalesce(col("is_kev").cast(IntegerType()), lit(0)))
    )


def compute_priority_score(
    df: DataFrame,
    cvss_weight: float = 0.4,
    epss_weight: float = 0.4,
    kev_weight: float = 0.2,
) -> DataFrame:
    """Compute an interpretable priority score using CVSS, EPSS and KEV."""
    return (
        df
        .withColumn("cvss_normalized", col("cvss_score") / lit(10.0))
        .withColumn(
            "priority_score",
            spark_round(
                (lit(cvss_weight) * col("cvss_normalized"))
                + (lit(epss_weight) * col("epss_score"))
                + (lit(kev_weight) * col("is_kev")),
                4,
            ),
        )
    )


def assign_priority_level(df: DataFrame) -> DataFrame:
    """Assign a categorical priority level from the numeric score."""
    return df.withColumn(
        "priority_level",
        when(col("priority_score") >= 0.8, "Critical")
        .when(col("priority_score") >= 0.6, "High")
        .when(col("priority_score") >= 0.4, "Medium")
        .otherwise("Low"),
    )


def build_scored_dataset(
    master_df: DataFrame,
    cvss_weight: float = 0.4,
    epss_weight: float = 0.4,
    kev_weight: float = 0.2,
) -> DataFrame:
    """Build the final scored vulnerability dataset."""
    scoring_df = prepare_scoring_columns(master_df)
    scoring_df = compute_priority_score(
        scoring_df,
        cvss_weight=cvss_weight,
        epss_weight=epss_weight,
        kev_weight=kev_weight,
    )
    scoring_df = assign_priority_level(scoring_df)
    return scoring_df


def save_scored_dataset(df: DataFrame, output_path: str) -> None:
    """Write the scored dataset to the gold layer."""
    print(f"Writing vulnerability scores to: {output_path}")
    df.write.mode("overwrite").parquet(output_path)
    print("Priority scoring completed.")
    print(f"Rows written: {df.count()}")


def run_priority_scoring(
    spark: SparkSession,
    input_path: str = DEFAULT_INPUT_PATH,
    output_path: str = DEFAULT_OUTPUT_PATH,
    cvss_weight: float = 0.4,
    epss_weight: float = 0.4,
    kev_weight: float = 0.2,
) -> DataFrame:
    """Run the full priority scoring job."""
    master_df = load_master_dataset(spark, input_path)
    scored_df = build_scored_dataset(
        master_df,
        cvss_weight=cvss_weight,
        epss_weight=epss_weight,
        kev_weight=kev_weight,
    )
    save_scored_dataset(scored_df, output_path)
    return scored_df


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Compute vulnerability priority scores.")
    parser.add_argument("--input-path", default=DEFAULT_INPUT_PATH)
    parser.add_argument("--output-path", default=DEFAULT_OUTPUT_PATH)
    parser.add_argument("--cvss-weight", type=float, default=0.4)
    parser.add_argument("--epss-weight", type=float, default=0.4)
    parser.add_argument("--kev-weight", type=float, default=0.2)
    return parser.parse_args()


def main() -> None:
    """Entry point for spark-submit."""
    args = parse_args()
    spark = create_spark_session()

    run_priority_scoring(
        spark=spark,
        input_path=args.input_path,
        output_path=args.output_path,
        cvss_weight=args.cvss_weight,
        epss_weight=args.epss_weight,
        kev_weight=args.kev_weight,
    )

    spark.stop()


if __name__ == "__main__":
    main()
