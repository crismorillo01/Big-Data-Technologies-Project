"""Remediation actions job — actionable ranking by vendor + product.

Auto-detects the latest available snapshot date so you never need to
pass --snapshot-date manually.
"""

from __future__ import annotations

import argparse
import logging
import math
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from pyspark.sql import DataFrame, SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import DateType
from pyspark.sql.window import Window

from src.config import (
    GOLD_REMEDIATION_ACTIONS_DIR,
    GOLD_VULN_SCORES_FINAL_DIR,
    configure_logging,
    create_spark_session,
    get_snapshot_date,
)

_log = logging.getLogger(__name__)

_UNKNOWN = "unknown"
_TOP_CVES = 5


# ---------------------------------------------------------------------------
# Auto-detect latest snapshot
# ---------------------------------------------------------------------------

def detect_snapshot_date(base_dir: Path, requested: str) -> str:
    """Return requested date if available, otherwise the latest partition date."""
    available = sorted([
        p.name.replace("snapshot_date=", "")
        for p in base_dir.iterdir()
        if p.is_dir() and p.name.startswith("snapshot_date=")
    ], reverse=True) if base_dir.exists() else []

    if not available:
        _log.warning("No snapshot partitions found in %s", base_dir)
        return requested
    if requested in available:
        return requested
    latest = available[0]
    _log.warning("No data for %s, using latest available: %s", requested, latest)
    return latest


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load_latest_scores(spark: SparkSession, snapshot_date: str) -> tuple[DataFrame, str]:
    """Load vulnerability_scores_final, auto-detecting the latest snapshot."""
    actual_date = detect_snapshot_date(GOLD_VULN_SCORES_FINAL_DIR, snapshot_date)
    _log.info("Loading vulnerability_scores_final for snapshot_date=%s", actual_date)
    df = (
        spark.read.parquet(str(GOLD_VULN_SCORES_FINAL_DIR))
        .filter(F.col("snapshot_date") == F.lit(actual_date).cast(DateType()))
    )
    return df, actual_date


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------

def normalise_groups(df: DataFrame) -> DataFrame:
    return (
        df
        .withColumn("primary_vendor",
                    F.coalesce(F.col("primary_vendor"), F.lit(_UNKNOWN)))
        .withColumn("primary_product",
                    F.coalesce(F.col("primary_product"), F.lit(_UNKNOWN)))
    )


# ---------------------------------------------------------------------------
# Core aggregation
# ---------------------------------------------------------------------------

def build_remediation_actions(df: DataFrame, top_cves: int = _TOP_CVES) -> DataFrame:
    w = Window.partitionBy("primary_vendor", "primary_product").orderBy(
        F.col("priority_score_final").desc()
    )
    df_ranked = df.withColumn("_group_rank", F.row_number().over(w))

    group_agg = df_ranked.groupBy("primary_vendor", "primary_product").agg(
        F.count("cve_id").alias("n_cves"),
        F.sum(F.when(F.col("is_kev") == 1, 1).otherwise(0)).alias("n_kev"),
        F.max("priority_score_final").alias("max_priority"),
        F.sum("priority_score_final").alias("sum_priority"),
        F.avg("epss_score").alias("mean_epss"),
        F.max("epss_score").alias("max_epss"),
        F.collect_list(
            F.when(F.col("_group_rank") <= top_cves, F.col("cve_id"))
        ).alias("top_cves_raw"),
    )

    return (
        group_agg
        .withColumn("effort_proxy", F.log1p(F.col("n_cves").cast("double")))
        .withColumn("action_score",
                    F.when(F.col("effort_proxy") > 0,
                           F.col("sum_priority") / F.col("effort_proxy"))
                    .otherwise(F.lit(0.0)))
        .withColumn("top_cves", F.array_compact(F.col("top_cves_raw")))
        .drop("top_cves_raw")
        .orderBy(F.col("action_score").desc())
    )


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------

def save_remediation_actions(df: DataFrame, snapshot_date: str) -> None:
    out = str(GOLD_REMEDIATION_ACTIONS_DIR)
    _log.info("Writing remediation_actions to %s (snapshot_date=%s)", out, snapshot_date)
    (
        df
        .withColumn("snapshot_date", F.to_date(F.lit(snapshot_date), "yyyy-MM-dd"))
        .write
        .partitionBy("snapshot_date")
        .mode("overwrite")
        .parquet(out)
    )
    _log.info("Remediation actions job complete.")


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def run_remediation_actions(
    spark: SparkSession,
    snapshot_date: str,
    top_cves: int = _TOP_CVES,
) -> DataFrame:
    df, actual_date = load_latest_scores(spark, snapshot_date)
    df = normalise_groups(df)
    actions = build_remediation_actions(df, top_cves=top_cves)
    save_remediation_actions(actions, actual_date)
    return actions


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build actionable remediation actions grouped by vendor+product."
    )
    parser.add_argument("--snapshot-date", default=get_snapshot_date(),
                        help="Snapshot date (YYYY-MM-DD). Auto-detects latest if not found.")
    parser.add_argument("--top-cves", type=int, default=_TOP_CVES)
    parser.add_argument("--driver-memory", default="3g")
    return parser.parse_args()


def main() -> None:
    configure_logging()
    args = parse_args()
    spark = create_spark_session("remediation-actions", driver_memory=args.driver_memory)
    try:
        run_remediation_actions(spark, args.snapshot_date, args.top_cves)
    finally:
        spark.stop()


if __name__ == "__main__":
    main()