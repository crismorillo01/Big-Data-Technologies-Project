"""Capacity simulation job — Spark implementation.

Reads ``vulnerability_scores_final`` for one snapshot and writes:

- ``remediation_recommendations/<strategy>/snapshot_date=YYYY-MM-DD/``
- ``strategy_comparison/snapshot_date=YYYY-MM-DD/``
- ``cluster_risk_summary/snapshot_date=YYYY-MM-DD/``
- ``simulation_timeseries/snapshot_date=YYYY-MM-DD/``
"""

from __future__ import annotations

import argparse
import logging
import math
import sys
from pathlib import Path

# Allow plain-script execution: `spark-submit src/optimization/capacity_simulation.py`
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from pyspark import StorageLevel
from pyspark.sql import DataFrame, SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import (
    DateType,
    DoubleType,
    IntegerType,
    LongType,
    StringType,
    StructField,
    StructType,
)
from pyspark.sql.window import Window

from src.config import (
    DEFAULT_ARRIVAL_RATE,
    DEFAULT_DAILY_CAPACITY,
    DEFAULT_SIMULATION_DAYS,
    GOLD_CLUSTER_RISK_SUMMARY_DIR,
    GOLD_REMEDIATION_RECOMMENDATIONS_DIR,
    GOLD_SIMULATION_TIMESERIES_DIR,
    GOLD_STRATEGY_COMPARISON_DIR,
    GOLD_VULN_SCORES_FINAL_DIR,
    configure_logging,
    create_spark_session,
    get_snapshot_date,
)

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Snapshot resolution
# ---------------------------------------------------------------------------

def detect_snapshot_date(base_dir: Path, requested: str) -> str:
    """Return requested snapshot if present, otherwise the latest available."""
    if not base_dir.exists():
        return requested
    available = sorted([
        p.name.replace("snapshot_date=", "")
        for p in base_dir.iterdir()
        if p.is_dir() and p.name.startswith("snapshot_date=")
    ], reverse=True)
    if not available:
        return requested
    if requested in available:
        return requested
    latest = available[0]
    _log.warning("No data for %s, using latest: %s", requested, latest)
    return latest


# ---------------------------------------------------------------------------
# Loading / writing
# ---------------------------------------------------------------------------

def load_scored(spark: SparkSession, snapshot_date: str) -> tuple[DataFrame, str]:
    """Load final scored vulnerabilities for one resolved snapshot."""
    actual_date = detect_snapshot_date(GOLD_VULN_SCORES_FINAL_DIR, snapshot_date)
    _log.info(
        "Loading vulnerability_scores_final from %s for snapshot_date=%s",
        GOLD_VULN_SCORES_FINAL_DIR,
        actual_date,
    )
    df = (
        spark.read.parquet(str(GOLD_VULN_SCORES_FINAL_DIR))
        .filter(F.col("snapshot_date") == F.lit(actual_date).cast(DateType()))
        .dropDuplicates(["cve_id"])
    )

    df = (
        df
        .withColumn(
            "priority_score_final",
            F.coalesce(F.col("priority_score_final").cast(DoubleType()), F.lit(0.0)),
        )
        .withColumn("epss_score", F.coalesce(F.col("epss_score").cast(DoubleType()), F.lit(0.0)))
        .withColumn("is_kev", F.coalesce(F.col("is_kev").cast(IntegerType()), F.lit(0)))
        .withColumn("cvss_score", F.coalesce(F.col("cvss_score").cast(DoubleType()), F.lit(0.0)))
    )
    if "cluster_id" in df.columns:
        df = df.withColumn("cluster_id", F.coalesce(F.col("cluster_id").cast(IntegerType()), F.lit(-1)))

    return df, actual_date


def write_partitioned(df: DataFrame, path: Path, snapshot_date: str) -> None:
    """Write a small gold output partitioned by snapshot_date."""
    path.mkdir(parents=True, exist_ok=True)
    (
        df.withColumn("snapshot_date", F.lit(snapshot_date).cast(DateType()))
        .coalesce(1)
        .write
        .mode("overwrite")
        .partitionBy("snapshot_date")
        .parquet(str(path))
    )


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

def strategy_top_priority(df: DataFrame, capacity: int) -> DataFrame:
    return df.orderBy(F.col("priority_score_final").desc()).limit(capacity)


def strategy_high_epss(df: DataFrame, capacity: int) -> DataFrame:
    return df.orderBy(F.col("epss_score").desc()).limit(capacity)


def strategy_cluster_based(df: DataFrame, capacity: int) -> DataFrame:
    if "cluster_id" not in df.columns:
        return strategy_top_priority(df, capacity)

    n_clusters = df.select("cluster_id").distinct().count()
    per_cluster = max(1, capacity // max(n_clusters, 1))
    w = Window.partitionBy("cluster_id").orderBy(F.col("priority_score_final").desc())
    selected = (
        df.withColumn("_cluster_rank", F.row_number().over(w))
        .filter(F.col("_cluster_rank") <= F.lit(per_cluster))
        .drop("_cluster_rank")
    )
    return selected.orderBy(F.col("priority_score_final").desc()).limit(capacity)


def strategy_kev_first(df: DataFrame, capacity: int) -> DataFrame:
    kev = df.filter(F.col("is_kev") == 1).orderBy(F.col("priority_score_final").desc()).limit(capacity)
    n_kev = kev.count()
    if n_kev >= capacity:
        return kev

    non_kev = (
        df.filter(F.col("is_kev") != 1)
        .orderBy(F.col("priority_score_final").desc())
        .limit(capacity - n_kev)
    )
    return kev.unionByName(non_kev)


def strategy_hybrid(df: DataFrame, capacity: int) -> DataFrame:
    kev_slots = max(1, capacity // 2)
    kev_part = strategy_kev_first(df, kev_slots).withColumn("_strategy_order", F.lit(0))
    cluster_part = strategy_cluster_based(df, capacity - kev_slots).withColumn("_strategy_order", F.lit(1))

    w = Window.partitionBy("cve_id").orderBy(
        F.col("_strategy_order").asc(),
        F.col("priority_score_final").desc(),
    )
    return (
        kev_part.unionByName(cluster_part)
        .withColumn("_dedupe_rank", F.row_number().over(w))
        .filter(F.col("_dedupe_rank") == 1)
        .orderBy(F.col("_strategy_order").asc(), F.col("priority_score_final").desc())
        .drop("_strategy_order", "_dedupe_rank")
        .limit(capacity)
    )


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def compute_metrics(df_full: DataFrame, df_selected: DataFrame, name: str) -> dict:
    n_kev_total = df_full.filter(F.col("is_kev") == 1).count()

    selected_metrics = df_selected.agg(
        F.count("*").cast(LongType()).alias("n_selected"),
        F.sum(F.when(F.col("is_kev") == 1, 1).otherwise(0)).cast(LongType()).alias("n_kev_selected"),
        F.sum("epss_score").cast(DoubleType()).alias("epss_expected_mitigated"),
        F.avg("priority_score_final").cast(DoubleType()).alias("mean_priority_selected"),
    ).collect()[0]

    n_selected = int(selected_metrics["n_selected"] or 0)
    n_kev_selected = int(selected_metrics["n_kev_selected"] or 0)
    epss_expected = float(selected_metrics["epss_expected_mitigated"] or 0.0)
    mean_priority = float(selected_metrics["mean_priority_selected"] or 0.0)

    entropy = 0.0
    if n_selected > 0 and "cluster_id" in df_selected.columns:
        cluster_counts = df_selected.groupBy("cluster_id").agg(F.count("*").alias("cluster_count"))
        entropy_row = (
            cluster_counts
            .withColumn("p", F.col("cluster_count") / F.lit(n_selected))
            .agg((-F.sum(F.col("p") * (F.log(F.col("p")) / F.lit(math.log(2.0))))).alias("entropy"))
            .collect()[0]
        )
        entropy = float(entropy_row["entropy"] or 0.0)

    return {
        "strategy": name,
        "kev_coverage": round(n_kev_selected / n_kev_total, 4) if n_kev_total else 0.0,
        "epss_expected_mitigated": round(epss_expected, 4),
        "cluster_diversity": round(entropy, 4),
        "mean_priority_selected": round(mean_priority, 4) if n_selected else 0.0,
        "n_selected": n_selected,
    }


def build_cluster_risk_summary(spark: SparkSession, df: DataFrame) -> DataFrame:
    if "cluster_id" not in df.columns:
        schema = StructType([
            StructField("cluster_id", IntegerType(), True),
            StructField("cluster_size", LongType(), True),
            StructField("avg_priority_final", DoubleType(), True),
            StructField("avg_cvss", DoubleType(), True),
            StructField("avg_epss", DoubleType(), True),
            StructField("max_epss", DoubleType(), True),
            StructField("kev_density", DoubleType(), True),
            StructField("n_kev", LongType(), True),
        ])
        return spark.createDataFrame([], schema)

    return (
        df.groupBy("cluster_id")
        .agg(
            F.count("cve_id").cast(LongType()).alias("cluster_size"),
            F.avg("priority_score_final").alias("avg_priority_final"),
            F.avg("cvss_score").alias("avg_cvss"),
            F.avg("epss_score").alias("avg_epss"),
            F.max("epss_score").alias("max_epss"),
            F.avg("is_kev").alias("kev_density"),
            F.sum("is_kev").cast(LongType()).alias("n_kev"),
        )
    )


# ---------------------------------------------------------------------------
# Multi-day simulation
# ---------------------------------------------------------------------------

def simulate_multi_day(
    spark: SparkSession,
    df: DataFrame,
    daily_capacity: int,
    n_days: int,
    arrival_rate: int,
    snapshot_date: str,
) -> None:
    """Write multi-day backlog metrics without growing an iterative lineage.

    Each strategy is converted to one deterministic ranking. Daily backlog
    metrics are then computed from rank cut-offs, which avoids the expensive
    loop of joins, unions and deduplications over the full vulnerability set.
    """
    _log.info("Running multi-day simulation: %d days", n_days)
    total_rows = df.count()
    total_kev = df.filter(F.col("is_kev") == 1).count()
    kev_rate = (total_kev / total_rows) if total_rows else 0.0
    rows = []

    for name in ("top_priority", "high_epss", "cluster_based", "kev_first", "hybrid"):
        ranked = build_strategy_ranking(df, name).persist(StorageLevel.MEMORY_AND_DISK)
        for day in range(1, n_days + 1):
            cutoff = daily_capacity * day
            mitigated = ranked.filter(F.col("_strategy_rank") <= F.lit(cutoff))
            metrics = mitigated.agg(
                F.count("*").cast(LongType()).alias("mitigated_count"),
                F.sum(F.when(F.col("is_kev") == 1, 1).otherwise(0)).cast(LongType()).alias("mitigated_kev"),
                F.sum("epss_score").cast(DoubleType()).alias("cumulative_epss"),
            ).collect()[0]

            mitigated_count = int(metrics["mitigated_count"] or 0)
            mitigated_kev = int(metrics["mitigated_kev"] or 0)
            cumulative_epss = float(metrics["cumulative_epss"] or 0.0)
            synthetic_arrivals = max(0, arrival_rate) * day
            synthetic_kev_arrivals = int(round(synthetic_arrivals * kev_rate))
            backlog_size = max(total_rows + synthetic_arrivals - mitigated_count, 0)
            kev_in_backlog = max(total_kev + synthetic_kev_arrivals - mitigated_kev, 0)

            rows.append((
                name,
                day,
                int(backlog_size),
                int(kev_in_backlog),
                round(cumulative_epss, 4),
                float(day),
            ))
        ranked.unpersist(blocking=True)

    schema = StructType([
        StructField("strategy", StringType(), False),
        StructField("day", IntegerType(), False),
        StructField("backlog_size", LongType(), False),
        StructField("kev_in_backlog", LongType(), False),
        StructField("cumulative_mitigated_epss", DoubleType(), False),
        StructField("mean_age_in_backlog", DoubleType(), False),
    ])
    write_partitioned(
        spark.createDataFrame(rows, schema),
        GOLD_SIMULATION_TIMESERIES_DIR,
        snapshot_date,
    )
    _log.info("Simulation timeseries written.")


def build_strategy_ranking(df: DataFrame, strategy: str) -> DataFrame:
    """Return the input rows with a 1-based rank for the selected strategy."""
    if strategy == "top_priority":
        ranked_source = df
        order_cols = [F.col("priority_score_final").desc(), F.col("cve_id").asc()]
    elif strategy == "high_epss":
        ranked_source = df
        order_cols = [
            F.col("epss_score").desc(),
            F.col("priority_score_final").desc(),
            F.col("cve_id").asc(),
        ]
    elif strategy == "kev_first":
        ranked_source = df
        order_cols = [
            F.col("is_kev").desc(),
            F.col("priority_score_final").desc(),
            F.col("cve_id").asc(),
        ]
    elif strategy == "cluster_based":
        if "cluster_id" not in df.columns:
            ranked_source = df
            order_cols = [F.col("priority_score_final").desc(), F.col("cve_id").asc()]
        else:
            cluster_w = Window.partitionBy("cluster_id").orderBy(
                F.col("priority_score_final").desc(),
                F.col("cve_id").asc(),
            )
            ranked_source = df.withColumn("_cluster_round", F.row_number().over(cluster_w))
            order_cols = [
                F.col("_cluster_round").asc(),
                F.col("priority_score_final").desc(),
                F.col("cluster_id").asc(),
                F.col("cve_id").asc(),
            ]
    elif strategy == "hybrid":
        if "cluster_id" not in df.columns:
            ranked_source = df.withColumn("_cluster_round", F.lit(1))
        else:
            cluster_w = Window.partitionBy("cluster_id").orderBy(
                F.col("priority_score_final").desc(),
                F.col("cve_id").asc(),
            )
            ranked_source = df.withColumn("_cluster_round", F.row_number().over(cluster_w))
        order_cols = [
            F.col("is_kev").desc(),
            F.col("_cluster_round").asc(),
            F.col("priority_score_final").desc(),
            F.col("cve_id").asc(),
        ]
    else:
        raise ValueError(f"Unknown strategy: {strategy}")

    rank_w = Window.orderBy(*order_cols)
    return ranked_source.withColumn("_strategy_rank", F.row_number().over(rank_w))


# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------

def run_capacity_simulation(
    spark: SparkSession,
    snapshot_date: str,
    daily_capacity: int = DEFAULT_DAILY_CAPACITY,
    simulation_days: int = DEFAULT_SIMULATION_DAYS,
    arrival_rate: int = DEFAULT_ARRIVAL_RATE,
) -> None:
    df, actual_date = load_scored(spark, snapshot_date)
    df = df.persist(StorageLevel.MEMORY_AND_DISK)
    total_rows = df.count()
    _log.info("Total CVEs: %d (snapshot_date=%s)", total_rows, actual_date)

    if total_rows == 0:
        _log.error("No data loaded — aborting.")
        df.unpersist(blocking=True)
        return

    strategy_map = {
        "top_priority": strategy_top_priority,
        "high_epss": strategy_high_epss,
        "cluster_based": strategy_cluster_based,
        "kev_first": strategy_kev_first,
        "hybrid": strategy_hybrid,
    }

    results = []
    for name, fn in strategy_map.items():
        selected = fn(df, daily_capacity).cache()
        metrics = compute_metrics(df, selected, name)
        results.append(metrics)
        _log.info(
            "Strategy %s: kev_coverage=%.2f, epss_mitigated=%.2f",
            name,
            metrics["kev_coverage"],
            metrics["epss_expected_mitigated"],
        )
        write_partitioned(
            selected,
            GOLD_REMEDIATION_RECOMMENDATIONS_DIR / name,
            actual_date,
        )
        selected.unpersist(blocking=True)

    strategy_schema = StructType([
        StructField("strategy", StringType(), False),
        StructField("kev_coverage", DoubleType(), False),
        StructField("epss_expected_mitigated", DoubleType(), False),
        StructField("cluster_diversity", DoubleType(), False),
        StructField("mean_priority_selected", DoubleType(), False),
        StructField("n_selected", LongType(), False),
    ])
    write_partitioned(
        spark.createDataFrame(results, strategy_schema),
        GOLD_STRATEGY_COMPARISON_DIR,
        actual_date,
    )
    _log.info("Strategy comparison written.")

    cluster_summary = build_cluster_risk_summary(spark, df)
    write_partitioned(cluster_summary, GOLD_CLUSTER_RISK_SUMMARY_DIR, actual_date)
    _log.info("Cluster risk summary written with %d clusters.", cluster_summary.count())

    simulate_multi_day(spark, df, daily_capacity, simulation_days, arrival_rate, actual_date)
    df.unpersist(blocking=True)
    _log.info("Capacity simulation job complete.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--snapshot-date", default=get_snapshot_date(),
        help="Snapshot date (YYYY-MM-DD). Auto-detects latest if not found.",
    )
    parser.add_argument("--daily-capacity", type=int, default=DEFAULT_DAILY_CAPACITY)
    parser.add_argument("--simulation-days", type=int, default=DEFAULT_SIMULATION_DAYS)
    parser.add_argument("--arrival-rate", type=int, default=DEFAULT_ARRIVAL_RATE)
    parser.add_argument(
        "--driver-memory",
        default="3g",
        help="Spark driver memory (e.g. 3g). Default: 3g.",
    )
    return parser.parse_args()


def main() -> None:
    configure_logging()
    args = parse_args()
    spark = create_spark_session("capacity-simulation", driver_memory=args.driver_memory)
    # This job intentionally uses global rankings for remediation strategies.
    # Keep Spark's repeated WindowExec performance warnings out of demo logs.
    spark.sparkContext.setLogLevel("ERROR")
    try:
        run_capacity_simulation(
            spark=spark,
            snapshot_date=args.snapshot_date,
            daily_capacity=args.daily_capacity,
            simulation_days=args.simulation_days,
            arrival_rate=args.arrival_rate,
        )
    finally:
        spark.stop()


if __name__ == "__main__":
    main()
