"""Tests for src/optimization/capacity_simulation.py."""

from __future__ import annotations

from src.optimization.capacity_simulation import (
    build_cluster_risk_summary,
    compute_metrics,
    strategy_cluster_based,
    strategy_high_epss,
    strategy_kev_first,
    strategy_top_priority,
)


def _scored_df(spark):
    rows = [
        ("CVE-001", 0.95, 0.90, 1, 9.8, 1),
        ("CVE-002", 0.80, 0.70, 1, 8.1, 1),
        ("CVE-003", 0.70, 0.95, 0, 7.5, 2),
        ("CVE-004", 0.60, 0.20, 0, 6.0, 2),
        ("CVE-005", 0.50, 0.10, 0, 5.0, 3),
    ]
    cols = [
        "cve_id", "priority_score_final", "epss_score",
        "is_kev", "cvss_score", "cluster_id",
    ]
    return spark.createDataFrame(rows, cols)


def test_strategy_top_priority_returns_highest_scores(spark):
    df = _scored_df(spark)
    rows = [r["cve_id"] for r in strategy_top_priority(df, 2).collect()]
    assert rows == ["CVE-001", "CVE-002"]


def test_strategy_high_epss_returns_highest_epss(spark):
    df = _scored_df(spark)
    rows = [r["cve_id"] for r in strategy_high_epss(df, 2).collect()]
    assert rows == ["CVE-003", "CVE-001"]


def test_strategy_cluster_based_takes_rows_from_multiple_clusters(spark):
    df = _scored_df(spark)
    rows = {r["cluster_id"] for r in strategy_cluster_based(df, 3).collect()}
    assert rows == {1, 2, 3}


def test_strategy_kev_first_prioritises_kev_rows(spark):
    df = _scored_df(spark)
    rows = [r["cve_id"] for r in strategy_kev_first(df, 3).collect()]
    assert rows[:2] == ["CVE-001", "CVE-002"]


def test_compute_metrics_returns_expected_counts(spark):
    df = _scored_df(spark)
    selected = strategy_top_priority(df, 2)
    metrics = compute_metrics(df, selected, "top_priority")
    assert metrics["strategy"] == "top_priority"
    assert metrics["n_selected"] == 2
    assert metrics["kev_coverage"] == 1.0


def test_cluster_risk_summary_groups_by_cluster(spark):
    df = _scored_df(spark)
    summary = build_cluster_risk_summary(spark, df)
    rows = {r["cluster_id"]: r for r in summary.collect()}
    assert rows[1]["cluster_size"] == 2
    assert rows[1]["n_kev"] == 2
    assert rows[2]["cluster_size"] == 2
