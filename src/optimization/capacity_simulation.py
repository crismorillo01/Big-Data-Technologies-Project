"""Capacity simulation job for vulnerability remediation.

This script simulates patching under resource constraints using the
clustered vulnerability dataset. It evaluates different remediation
strategies and compares their effectiveness in reducing overall risk.
"""

import argparse
from pyspark.sql import SparkSession
from pyspark.sql.functions import col, sum as spark_sum, avg


# Spark session
def create_spark_session(app_name: str = "capacity-simulation") -> SparkSession:
    spark = (
        SparkSession.builder
        .appName(app_name)
        .config("spark.driver.memory", "4g")
        .config("spark.executor.memory", "4g")
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("WARN")
    return spark


# Strategies
def strategy_top_priority(df, capacity):
    """Select top vulnerabilities by priority score."""
    return df.orderBy(col("priority_score").desc()).limit(capacity)


def strategy_high_epss(df, capacity):
    """Select vulnerabilities with highest exploit probability."""
    return df.orderBy(col("epss_score").desc()).limit(capacity)


def strategy_cluster_based(df, capacity):
    """Select vulnerabilities evenly across clusters."""
    clusters = [row["cluster_id"]
                for row in df.select("cluster_id").distinct().collect()]
    per_cluster = max(1, capacity // len(clusters))

    selected = None
    for c in clusters:
        subset = (
            df.filter(col("cluster_id") == c)
            .orderBy(col("priority_score").desc())
            .limit(per_cluster)
        )
        selected = subset if selected is None else selected.union(subset)

    return selected.limit(capacity)


# Evaluation
def evaluate_strategy(df_full, df_selected):
    """Compute risk reduction."""
    total_risk = df_full.agg(spark_sum("priority_score")).collect()[0][0]
    mitigated_risk = df_selected.agg(
        spark_sum("priority_score")).collect()[0][0]

    reduction = mitigated_risk / total_risk if total_risk else 0

    return {
        "total_risk": total_risk,
        "mitigated_risk": mitigated_risk,
        "reduction_ratio": reduction
    }


# Main logic
def run_capacity_simulation(
    spark,
    input_path,
    output_base,
    daily_capacity
):
    print("Loading clustered vulnerabilities...")
    df = spark.read.parquet(input_path)

    print(f"Total vulnerabilities: {df.count()}")

    # Apply strategies
    print("Running strategies...")

    top_priority = strategy_top_priority(df, daily_capacity)
    high_epss = strategy_high_epss(df, daily_capacity)
    cluster_based = strategy_cluster_based(df, daily_capacity)

    # Evaluate
    print("Evaluating strategies...")

    results = []

    for name, strat_df in [
        ("top_priority", top_priority),
        ("high_epss", high_epss),
        ("cluster_based", cluster_based)
    ]:
        metrics = evaluate_strategy(df, strat_df)
        metrics["strategy"] = name
        results.append(metrics)

    results_df = spark.createDataFrame(results)

    # Cluster risk summary
    cluster_summary = df.groupBy("cluster_id").agg(
        avg("priority_score").alias("avg_priority"),
        avg("cvss_score").alias("avg_cvss"),
        avg("epss_score").alias("avg_epss")
    )

    # Write outputs
    print("Writing outputs...")

    results_df.write.mode("overwrite").parquet(
        f"{output_base}/strategy_comparison"
    )

    cluster_summary.write.mode("overwrite").parquet(
        f"{output_base}/cluster_risk_summary"
    )

    top_priority.write.mode("overwrite").parquet(
        f"{output_base}/remediation_recommendations/top_priority"
    )

    high_epss.write.mode("overwrite").parquet(
        f"{output_base}/remediation_recommendations/high_epss"
    )

    cluster_based.write.mode("overwrite").parquet(
        f"{output_base}/remediation_recommendations/cluster_based"
    )

    print("Capacity simulation completed.")


# -------------------------
# Entry point
# -------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input-path",
        default="data/prod/gold/vulnerabilities_clustered"
    )
    parser.add_argument(
        "--output-base",
        default="data/prod/gold"
    )
    parser.add_argument(
        "--daily-capacity",
        type=int,
        default=50
    )

    args = parser.parse_args()

    spark = create_spark_session()

    run_capacity_simulation(
        spark,
        args.input_path,
        args.output_base,
        args.daily_capacity
    )

    spark.stop()
