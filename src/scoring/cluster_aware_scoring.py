"""Cluster-aware scoring job — sandwich scoring refinement.

Reads vulnerabilities_clustered (which already has cluster_id + priority_score),
computes per-cluster risk signals, and produces priority_score_final by boosting
scores in high-risk clusters. Writes to vulnerability_scores_final/.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

# Allow `spark-submit src/scoring/cluster_aware_scoring.py` to find the src package.
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from pyspark.sql import DataFrame, SparkSession
from pyspark.sql.functions import (
    avg,
    col,
    greatest,
    least,
    lit,
    max as spark_max,
    sum as spark_sum,
    when,
)
from pyspark.sql.types import DateType

from src.config import (
    DEFAULT_CLUSTER_EPSS_BETA,
    DEFAULT_CLUSTER_KEV_ALPHA,
    GOLD_VULN_CLUSTERED_DIR,
    GOLD_VULN_SCORES_FINAL_DIR,
    PRIORITY_FINAL_MAX,
    PRIORITY_LEVEL_THRESHOLDS,
    configure_logging,
    create_spark_session,
    get_snapshot_date,
)

_log = logging.getLogger(__name__)


def load_clustered(spark: SparkSession) -> DataFrame:
    """Load the clustered vulnerability dataset."""
    _log.info("Loading clustered vulnerabilities from %s", GOLD_VULN_CLUSTERED_DIR)
    return spark.read.parquet(str(GOLD_VULN_CLUSTERED_DIR))


def compute_cluster_stats(df: DataFrame) -> DataFrame:
    """Compute per-cluster risk aggregates and join back onto every row."""
    cluster_stats = df.groupBy("cluster_id").agg(
        spark_sum(lit(1)).alias("cluster_size"),
        avg("is_kev").alias("cluster_kev_density"),
        spark_max("epss_score").alias("cluster_epss_max"),
        avg("epss_score").alias("cluster_epss_mean"),
        avg("cvss_score").alias("cluster_avg_cvss"),
    )
    return df.join(cluster_stats, on="cluster_id", how="left")


def compute_final_score(
    df: DataFrame,
    alpha: float = DEFAULT_CLUSTER_KEV_ALPHA,
    beta: float = DEFAULT_CLUSTER_EPSS_BETA,
) -> DataFrame:
    """Apply the sandwich formula and clip to [0, PRIORITY_FINAL_MAX].

    priority_score_final = priority_score * (1 + alpha * cluster_kev_density)
                         + beta * cluster_epss_max
    clipped to [0.0, PRIORITY_FINAL_MAX]
    """
    raw_final = (
        col("priority_score") * (lit(1.0) + lit(alpha) * col("cluster_kev_density"))
        + lit(beta) * col("cluster_epss_max")
    )
    return df.withColumn(
        "priority_score_final",
        least(lit(PRIORITY_FINAL_MAX), greatest(lit(0.0), raw_final)),
    )


def assign_final_priority_level(df: DataFrame) -> DataFrame:
    """Assign priority_level_final using the same thresholds as the base level."""
    critical = PRIORITY_LEVEL_THRESHOLDS["Critical"]
    high     = PRIORITY_LEVEL_THRESHOLDS["High"]
    medium   = PRIORITY_LEVEL_THRESHOLDS["Medium"]
    return df.withColumn(
        "priority_level_final",
        when(col("priority_score_final") >= critical, "Critical")
        .when(col("priority_score_final") >= high,    "High")
        .when(col("priority_score_final") >= medium,  "Medium")
        .otherwise("Low"),
    )


def build_final_scored_dataset(
    df: DataFrame,
    alpha: float = DEFAULT_CLUSTER_KEV_ALPHA,
    beta: float = DEFAULT_CLUSTER_EPSS_BETA,
) -> DataFrame:
    """Compute cluster stats, apply sandwich formula, assign final level."""
    df = compute_cluster_stats(df)
    df = compute_final_score(df, alpha, beta)
    return assign_final_priority_level(df)


def save_final_scores(df: DataFrame, snapshot_date: str) -> None:
    """Write the final scored dataset partitioned by snapshot_date."""
    out = str(GOLD_VULN_SCORES_FINAL_DIR)
    _log.info("Writing final scores to %s (snapshot_date=%s)", out, snapshot_date)
    (
        df.withColumn("snapshot_date", lit(snapshot_date).cast(DateType()))
        .write
        .partitionBy("snapshot_date")
        .mode("overwrite")
        .parquet(out)
    )
    _log.info("Cluster-aware scoring complete.")


def run_cluster_aware_scoring(
    spark: SparkSession,
    snapshot_date: str,
    alpha: float = DEFAULT_CLUSTER_KEV_ALPHA,
    beta: float = DEFAULT_CLUSTER_EPSS_BETA,
) -> DataFrame:
    """Orchestrate the full cluster-aware scoring job."""
    df = load_clustered(spark)
    df = build_final_scored_dataset(df, alpha, beta)
    save_final_scores(df, snapshot_date)
    return df


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compute cluster-aware final priority scores.")
    parser.add_argument("--snapshot-date", default=get_snapshot_date())
    parser.add_argument("--alpha", type=float, default=DEFAULT_CLUSTER_KEV_ALPHA,
                        help="KEV density boost coefficient.")
    parser.add_argument("--beta",  type=float, default=DEFAULT_CLUSTER_EPSS_BETA,
                        help="Cluster EPSS-max additive coefficient.")
    parser.add_argument("--driver-memory", default="3g",
                        help="Spark driver memory (e.g. 3g). Default: 3g.")
    return parser.parse_args()


def main() -> None:
    configure_logging()
    args = parse_args()
    spark = create_spark_session("cluster-aware-scoring", driver_memory=args.driver_memory)
    try:
        run_cluster_aware_scoring(spark, args.snapshot_date, args.alpha, args.beta)
    finally:
        spark.stop()


if __name__ == "__main__":
    main()
