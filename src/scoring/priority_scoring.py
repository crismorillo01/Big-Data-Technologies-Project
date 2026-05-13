"""Priority scoring job for vulnerability remediation.

Reads the gold-layer master_vulnerabilities, computes an interpretable priority
score from CVSS, EPSS percentile, KEV flag, and optional recency decay, then
writes the scored dataset back to the gold layer partitioned by snapshot_date.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

# Allow `spark-submit src/scoring/priority_scoring.py` to find the src package.
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from pyspark.sql import DataFrame, SparkSession
from pyspark.sql.functions import (
    coalesce,
    col,
    current_date,
    datediff,
    greatest,
    lit,
    round as spark_round,
    when,
)
from pyspark.sql.types import DateType, DoubleType, IntegerType

from src.config import (
    DEFAULT_CVSS_WEIGHT,
    DEFAULT_EPSS_WEIGHT,
    DEFAULT_KEV_OVERRIDE_FLOOR,
    DEFAULT_KEV_WEIGHT,
    DEFAULT_RECENCY_WEIGHT,
    GOLD_MASTER_DIR,
    GOLD_VULN_SCORES_DIR,
    PRIORITY_LEVEL_THRESHOLDS,
    configure_logging,
    create_spark_session,
    get_snapshot_date,
)

_log = logging.getLogger(__name__)


def load_master_dataset(spark: SparkSession) -> DataFrame:
    """Load the full master vulnerability dataset."""
    _log.info("Loading master dataset from %s", GOLD_MASTER_DIR)
    return spark.read.parquet(str(GOLD_MASTER_DIR))


def prepare_scoring_columns(df: DataFrame) -> DataFrame:
    """Cast and fill columns needed for scoring.

    join_master already applies defaults, but we re-coalesce here so the
    function is safe when called with synthetic test DataFrames too.
    """
    return (
        df
        .withColumn("cvss_score",     coalesce(col("cvss_score").cast(DoubleType()),     lit(0.0)))
        .withColumn("epss_percentile", coalesce(col("epss_percentile").cast(DoubleType()), lit(0.0)))
        .withColumn("is_kev",          coalesce(col("is_kev").cast(IntegerType()),          lit(0)))
    )


def compute_priority_score(
    df: DataFrame,
    cvss_weight: float = DEFAULT_CVSS_WEIGHT,
    epss_weight: float = DEFAULT_EPSS_WEIGHT,
    kev_weight: float = DEFAULT_KEV_WEIGHT,
    recency_weight: float = DEFAULT_RECENCY_WEIGHT,
) -> DataFrame:
    """Compute the base priority score and apply the KEV override floor.

    Formula:
        score = cvss_weight*(cvss/10) + epss_weight*epss_percentile
              + kev_weight*is_kev + recency_weight*recency_score
        if is_kev == 1: score = max(score, KEV_OVERRIDE_FLOOR)

    recency_score decays linearly from 1.0 (published today) to 0.0
    (published 3+ years ago), so older CVEs are not penalised below zero.
    """
    recency_score = greatest(
        lit(0.0),
        lit(1.0) - datediff(current_date(), col("published").cast(DateType())) / lit(1095.0),
    )

    df = (
        df
        .withColumn("cvss_normalized", col("cvss_score") / lit(10.0))
        .withColumn("recency_score", recency_score)
        .withColumn(
            "priority_score",
            spark_round(
                lit(cvss_weight)      * col("cvss_normalized")
                + lit(epss_weight)    * col("epss_percentile")
                + lit(kev_weight)     * col("is_kev")
                + lit(recency_weight) * col("recency_score"),
                4,
            ),
        )
    )

    # KEV override: any CVE in the CISA KEV list gets at least this floor score.
    return df.withColumn(
        "priority_score",
        when(col("is_kev") == 1, greatest(col("priority_score"), lit(DEFAULT_KEV_OVERRIDE_FLOOR)))
        .otherwise(col("priority_score")),
    )


def assign_priority_level(df: DataFrame) -> DataFrame:
    """Assign a categorical priority level from the numeric score."""
    critical = PRIORITY_LEVEL_THRESHOLDS["Critical"]
    high     = PRIORITY_LEVEL_THRESHOLDS["High"]
    medium   = PRIORITY_LEVEL_THRESHOLDS["Medium"]
    return df.withColumn(
        "priority_level",
        when(col("priority_score") >= critical, "Critical")
        .when(col("priority_score") >= high,    "High")
        .when(col("priority_score") >= medium,  "Medium")
        .otherwise("Low"),
    )


def build_scored_dataset(
    master_df: DataFrame,
    cvss_weight: float = DEFAULT_CVSS_WEIGHT,
    epss_weight: float = DEFAULT_EPSS_WEIGHT,
    kev_weight: float = DEFAULT_KEV_WEIGHT,
    recency_weight: float = DEFAULT_RECENCY_WEIGHT,
) -> DataFrame:
    """Prepare, score, and level the full master dataset."""
    df = prepare_scoring_columns(master_df)
    df = compute_priority_score(df, cvss_weight, epss_weight, kev_weight, recency_weight)
    return assign_priority_level(df)


def save_scored_dataset(df: DataFrame, snapshot_date: str) -> None:
    """Write the scored dataset to the gold layer, partitioned by snapshot_date."""
    out = str(GOLD_VULN_SCORES_DIR)
    _log.info("Writing vulnerability scores to %s (snapshot_date=%s)", out, snapshot_date)
    (
        df.withColumn("snapshot_date", lit(snapshot_date).cast(DateType()))
        .write
        .partitionBy("snapshot_date")
        .mode("overwrite")
        .parquet(out)
    )
    _log.info("Priority scoring complete.")


def run_priority_scoring(
    spark: SparkSession,
    snapshot_date: str,
    cvss_weight: float = DEFAULT_CVSS_WEIGHT,
    epss_weight: float = DEFAULT_EPSS_WEIGHT,
    kev_weight: float = DEFAULT_KEV_WEIGHT,
    recency_weight: float = DEFAULT_RECENCY_WEIGHT,
) -> DataFrame:
    """Run the full priority scoring job and return the scored DataFrame."""
    master_df = load_master_dataset(spark)
    scored_df = build_scored_dataset(master_df, cvss_weight, epss_weight, kev_weight, recency_weight)
    save_scored_dataset(scored_df, snapshot_date)
    return scored_df


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compute vulnerability priority scores.")
    parser.add_argument("--snapshot-date",  default=get_snapshot_date())
    parser.add_argument("--cvss-weight",    type=float, default=DEFAULT_CVSS_WEIGHT)
    parser.add_argument("--epss-weight",    type=float, default=DEFAULT_EPSS_WEIGHT)
    parser.add_argument("--kev-weight",     type=float, default=DEFAULT_KEV_WEIGHT)
    parser.add_argument("--recency-weight", type=float, default=DEFAULT_RECENCY_WEIGHT)
    parser.add_argument("--driver-memory",  default="3g",
                        help="Spark driver memory (e.g. 3g). Default: 3g.")
    return parser.parse_args()


def main() -> None:
    configure_logging()
    args = parse_args()
    spark = create_spark_session("priority-scoring", driver_memory=args.driver_memory)
    try:
        run_priority_scoring(
            spark,
            snapshot_date=args.snapshot_date,
            cvss_weight=args.cvss_weight,
            epss_weight=args.epss_weight,
            kev_weight=args.kev_weight,
            recency_weight=args.recency_weight,
        )
    finally:
        spark.stop()


if __name__ == "__main__":
    main()
