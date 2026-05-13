"""Tests for src/scoring/priority_scoring.py."""

from __future__ import annotations

import datetime as dt

from src.scoring.priority_scoring import (
    assign_priority_level,
    compute_priority_score,
    prepare_scoring_columns,
)


def _base_df(spark):
    rows = [
        # cve_id, cvss_score, epss_percentile, is_kev, published
        ("CVE-A", 9.8, 0.95, 1, dt.datetime(2025, 1, 1)),  # KEV, high scores, recent
        ("CVE-B", 2.0, 0.01, 0, dt.datetime(2020, 1, 1)),  # low scores, old
        ("CVE-C", 7.5, 0.50, 0, dt.datetime(2026, 1, 1)),  # no KEV, very recent
        ("CVE-D", 0.0, 0.0,  1, dt.datetime(2026, 1, 1)),  # KEV but zero CVSS/EPSS
    ]
    cols = ["cve_id", "cvss_score", "epss_percentile", "is_kev", "published"]
    return spark.createDataFrame(rows, cols)


def test_kev_override_floor_applied(spark):
    df = prepare_scoring_columns(_base_df(spark))
    # Set all weights to 0 so raw score is 0 for every CVE.
    scored = compute_priority_score(df, cvss_weight=0.0, epss_weight=0.0,
                                    kev_weight=0.0, recency_weight=0.0)
    rows = {r["cve_id"]: r for r in scored.collect()}
    # CVE-D: is_kev=1, raw score=0 → KEV override must push score to ≥ 0.9
    assert rows["CVE-D"]["priority_score"] >= 0.9
    # CVE-B: is_kev=0, raw score=0 → no override, stays 0
    assert rows["CVE-B"]["priority_score"] == 0.0


def test_recency_boosts_recent_cve(spark):
    df = prepare_scoring_columns(_base_df(spark))
    scored = compute_priority_score(df, cvss_weight=0.0, epss_weight=0.0,
                                    kev_weight=0.0, recency_weight=0.5)
    rows = {r["cve_id"]: r for r in scored.collect()}
    # CVE-C published 2026-01-01 (nearly today) vs CVE-B published 2020-01-01 (6+ years ago)
    assert rows["CVE-C"]["priority_score"] > rows["CVE-B"]["priority_score"]


def test_priority_levels_at_boundaries(spark):
    rows = [
        ("CVE-1", 0.80),  # exactly Critical threshold
        ("CVE-2", 0.79),  # just below Critical → High
        ("CVE-3", 0.60),  # exactly High threshold
        ("CVE-4", 0.40),  # exactly Medium threshold
        ("CVE-5", 0.39),  # just below Medium → Low
    ]
    df = spark.createDataFrame(rows, ["cve_id", "priority_score"])
    leveled = {r["cve_id"]: r["priority_level"] for r in assign_priority_level(df).collect()}
    assert leveled["CVE-1"] == "Critical"
    assert leveled["CVE-2"] == "High"
    assert leveled["CVE-3"] == "High"
    assert leveled["CVE-4"] == "Medium"
    assert leveled["CVE-5"] == "Low"


def test_uses_epss_percentile_not_raw_score(spark):
    rows = [
        # CVE-X: high percentile (0.9), low raw epss_score (0.1)
        # CVE-Y: low percentile (0.1), high raw epss_score (0.9)
        ("CVE-X", 5.0, 0.9, 0.1, 0, dt.datetime(2024, 1, 1)),
        ("CVE-Y", 5.0, 0.1, 0.9, 0, dt.datetime(2024, 1, 1)),
    ]
    cols = ["cve_id", "cvss_score", "epss_percentile", "epss_score", "is_kev", "published"]
    df = prepare_scoring_columns(spark.createDataFrame(rows, cols))
    scored = compute_priority_score(df, cvss_weight=0.0, epss_weight=1.0,
                                    kev_weight=0.0, recency_weight=0.0)
    rows_out = {r["cve_id"]: r for r in scored.collect()}
    # Formula uses epss_percentile → CVE-X (0.9) must outscore CVE-Y (0.1)
    assert rows_out["CVE-X"]["priority_score"] > rows_out["CVE-Y"]["priority_score"]
