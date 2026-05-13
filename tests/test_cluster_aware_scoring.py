"""Tests for src/scoring/cluster_aware_scoring.py."""

from __future__ import annotations

from src.config import PRIORITY_FINAL_MAX
from src.scoring.cluster_aware_scoring import (
    assign_final_priority_level,
    build_final_scored_dataset,
    compute_cluster_stats,
    compute_final_score,
)


def _clustered_df(spark):
    rows = [
        # cve_id, cluster_id, priority_score, is_kev, epss_score, cvss_score
        ("CVE-1", 0, 0.5, 1, 0.9, 9.0),  # cluster 0: all KEV, high EPSS
        ("CVE-2", 0, 0.4, 1, 0.8, 8.0),
        ("CVE-3", 1, 0.3, 0, 0.1, 4.0),  # cluster 1: no KEV, low EPSS
        ("CVE-4", 1, 0.2, 0, 0.1, 3.0),
    ]
    cols = ["cve_id", "cluster_id", "priority_score", "is_kev", "epss_score", "cvss_score"]
    return spark.createDataFrame(rows, cols)


def test_kev_dense_cluster_boosts_scores(spark):
    df = build_final_scored_dataset(_clustered_df(spark), alpha=0.5, beta=0.1)
    rows = {r["cve_id"]: r for r in df.collect()}
    # cluster 0 has kev_density=1.0 → final score must exceed base score
    assert rows["CVE-1"]["priority_score_final"] > rows["CVE-1"]["priority_score"]


def test_low_kev_cluster_never_penalised(spark):
    df = build_final_scored_dataset(_clustered_df(spark), alpha=0.5, beta=0.1)
    rows = {r["cve_id"]: r for r in df.collect()}
    # cluster 1 has kev_density=0.0 → final ≥ base (additive beta term, never negative)
    assert rows["CVE-3"]["priority_score_final"] >= rows["CVE-3"]["priority_score"]


def test_priority_score_final_clipped_to_max(spark):
    # Construct a row whose raw final would exceed PRIORITY_FINAL_MAX.
    rows = [("CVE-X", 0, 1.4, 0, 1.0, 10.0)]
    cols = ["cve_id", "cluster_id", "priority_score", "is_kev", "epss_score", "cvss_score"]
    df = spark.createDataFrame(rows, cols)
    df = compute_cluster_stats(df)
    df = compute_final_score(df, alpha=0.5, beta=0.5)
    assert df.collect()[0]["priority_score_final"] <= PRIORITY_FINAL_MAX


def test_both_scores_present_in_output(spark):
    df = build_final_scored_dataset(_clustered_df(spark))
    assert "priority_score" in df.columns
    assert "priority_score_final" in df.columns
    assert "priority_level_final" in df.columns


def test_final_level_follows_thresholds(spark):
    rows = [
        ("CVE-A", 0, 0.85),
        ("CVE-B", 0, 0.65),
        ("CVE-C", 0, 0.45),
        ("CVE-D", 0, 0.25),
    ]
    cols = ["cve_id", "cluster_id", "priority_score_final"]
    df = spark.createDataFrame(rows, cols)
    leveled = {r["cve_id"]: r["priority_level_final"]
               for r in assign_final_priority_level(df).collect()}
    assert leveled["CVE-A"] == "Critical"
    assert leveled["CVE-B"] == "High"
    assert leveled["CVE-C"] == "Medium"
    assert leveled["CVE-D"] == "Low"
