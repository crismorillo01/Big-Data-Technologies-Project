"""Data quality metrics job for the vulnerability intelligence pipeline.

Reads the gold-layer master_vulnerabilities dataset and computes per-snapshot
quality metrics: completeness, source intersection sizes, severity distribution,
and EPSS statistics. Writes results to data/gold/data_quality/.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

# Allow `spark-submit src/processing/data_quality.py` to find the src package.
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from pyspark.sql import DataFrame, SparkSession
from pyspark.sql.functions import (
    avg,
    col,
    count,
    countDistinct,
    lit,
    percentile_approx,
    size,
    sum as spark_sum,
    when,
    year,
)

from src.config import (
    GOLD_DATA_QUALITY_DIR,
    GOLD_MASTER_DIR,
    configure_logging,
    create_spark_session,
    get_snapshot_date,
)

_log = logging.getLogger(__name__)


def load_master(spark: SparkSession, snapshot_date: str) -> DataFrame:
    """Load master vulnerabilities for a specific snapshot date."""
    _log.info("Loading master dataset from %s (snapshot_date=%s)", GOLD_MASTER_DIR, snapshot_date)
    return (
        spark.read.parquet(str(GOLD_MASTER_DIR))
        .filter(col("snapshot_date") == lit(snapshot_date))
    )


def compute_summary_metrics(df: DataFrame, snapshot_date: str) -> DataFrame:
    """Compute a single-row summary of quality metrics for the snapshot.

    Uses count("*") inline so all metrics are computed in a single Spark action.
    """
    n = count("*")
    return df.agg(
        lit(snapshot_date).alias("snapshot_date"),
        n.alias("row_count"),
        countDistinct("cve_id").alias("distinct_cve_count"),
        (spark_sum(when(col("cvss_score").isNull(), 1).otherwise(0)) * 100.0 / n)
            .alias("pct_null_cvss"),
        (spark_sum(when(col("epss_score") == 0.0, 1).otherwise(0)) * 100.0 / n)
            .alias("pct_null_epss"),
        (spark_sum(when(
            col("cwes").isNull() | (size(col("cwes")) == 0), 1
        ).otherwise(0)) * 100.0 / n).alias("pct_null_cwes"),
        (spark_sum(when(
            col("cpe_vendors").isNull() | (size(col("cpe_vendors")) == 0), 1
        ).otherwise(0)) * 100.0 / n).alias("pct_null_cpe"),
        (spark_sum(when(col("epss_score") > 0.7, 1).otherwise(0)) * 100.0 / n)
            .alias("pct_epss_gt_07"),
        (spark_sum(when(col("epss_score") > 0.9, 1).otherwise(0)) * 100.0 / n)
            .alias("pct_epss_gt_09"),
        avg("epss_score").alias("mean_epss"),
        percentile_approx("epss_score", 0.5).alias("median_epss"),
        spark_sum("is_kev").cast("long").alias("kev_count"),
        spark_sum(when(col("is_kev") == 1, 1).otherwise(0)).cast("long")
            .alias("nvd_kev_intersection"),
        spark_sum(when(col("epss_score") > 0.0, 1).otherwise(0)).cast("long")
            .alias("nvd_epss_intersection"),
        spark_sum(when(
            (col("is_kev") == 1) & (col("epss_score") > 0.0), 1
        ).otherwise(0)).cast("long").alias("nvd_kev_epss_intersection"),
    )


def compute_severity_distribution(df: DataFrame, snapshot_date: str) -> DataFrame:
    """Count CVEs per CVSS severity level."""
    return (
        df.groupBy("cvss_severity")
        .agg(count("*").alias("cve_count"))
        .withColumn("snapshot_date", lit(snapshot_date))
    )


def compute_kev_by_year(df: DataFrame, snapshot_date: str) -> DataFrame:
    """Count KEV CVEs by the year they were added to the KEV catalogue."""
    return (
        df.filter(col("is_kev") == 1)
        .withColumn("kev_year", year(col("kev_date_added")))
        .groupBy("kev_year")
        .agg(count("*").alias("kev_count"))
        .withColumn("snapshot_date", lit(snapshot_date))
    )


def save_metrics(
    summary_df: DataFrame,
    severity_df: DataFrame,
    kev_year_df: DataFrame,
    snapshot_date: str,
) -> None:
    """Write all three metric DataFrames partitioned by snapshot_date."""
    out_base = str(GOLD_DATA_QUALITY_DIR)
    _log.info("Writing data quality metrics to %s", out_base)

    (summary_df
     .write
     .partitionBy("snapshot_date")
     .mode("overwrite")
     .parquet(out_base + "/summary"))

    (severity_df
     .write
     .partitionBy("snapshot_date")
     .mode("overwrite")
     .parquet(out_base + "/severity_distribution"))

    (kev_year_df
     .write
     .partitionBy("snapshot_date")
     .mode("overwrite")
     .parquet(out_base + "/kev_by_year"))

    _log.info("Data quality job complete for snapshot_date=%s", snapshot_date)


def run_data_quality(spark: SparkSession, snapshot_date: str) -> None:
    """Orchestrate the full data quality job for one snapshot."""
    df = load_master(spark, snapshot_date)
    df.cache()
    try:
        summary_df = compute_summary_metrics(df, snapshot_date)
        severity_df = compute_severity_distribution(df, snapshot_date)
        kev_year_df = compute_kev_by_year(df, snapshot_date)
        save_metrics(summary_df, severity_df, kev_year_df, snapshot_date)
    finally:
        df.unpersist()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compute data quality metrics.")
    parser.add_argument(
        "--snapshot-date",
        default=get_snapshot_date(),
        help="Snapshot date to process (YYYY-MM-DD). Defaults to today UTC.",
    )
    parser.add_argument(
        "--driver-memory", default="3g",
        help="Spark driver memory (e.g. 3g). Default: 3g.",
    )
    return parser.parse_args()


def main() -> None:
    configure_logging()
    args = parse_args()
    spark = create_spark_session("data-quality", driver_memory=args.driver_memory)
    try:
        run_data_quality(spark, args.snapshot_date)
    finally:
        spark.stop()


if __name__ == "__main__":
    main()
