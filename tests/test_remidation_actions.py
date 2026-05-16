"""Tests for src/optimization/remediation_actions.py."""

from __future__ import annotations

import math

import pytest

from src.optimization.remediation_actions import (
    build_remediation_actions,
    normalise_groups,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _scores_df(spark):
    """Minimal scored DataFrame that mimics vulnerability_scores_final."""
    rows = [
        # cve_id, priority_score_final, is_kev, epss_score, primary_vendor, primary_product
        ("CVE-001", 0.95, 1, 0.9, "microsoft", "windows"),
        ("CVE-002", 0.80, 1, 0.7, "microsoft", "windows"),
        ("CVE-003", 0.70, 0, 0.5, "microsoft", "windows"),
        ("CVE-004", 0.60, 0, 0.3, "apache",    "httpd"),
        ("CVE-005", 0.50, 0, 0.2, "apache",    "httpd"),
        ("CVE-006", 0.40, 0, 0.1, None,         None),   # no CPE → should become 'unknown'
    ]
    cols = ["cve_id", "priority_score_final", "is_kev", "epss_score", "primary_vendor", "primary_product"]
    return spark.createDataFrame(rows, cols)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_normalise_groups_fills_unknown(spark):
    """Rows with null vendor/product should get the 'unknown' sentinel."""
    df = _scores_df(spark)
    normalised = normalise_groups(df)
    rows = {r["cve_id"]: r for r in normalised.collect()}
    assert rows["CVE-006"]["primary_vendor"] == "unknown"
    assert rows["CVE-006"]["primary_product"] == "unknown"


def test_normalise_groups_keeps_known_values(spark):
    """Rows with CPE data must not be overwritten."""
    df = _scores_df(spark)
    normalised = normalise_groups(df)
    rows = {r["cve_id"]: r for r in normalised.collect()}
    assert rows["CVE-001"]["primary_vendor"] == "microsoft"
    assert rows["CVE-001"]["primary_product"] == "windows"


def test_grouping_produces_correct_n_cves(spark):
    """Each action row must count the right number of CVEs in the group."""
    df = normalise_groups(_scores_df(spark))
    actions = build_remediation_actions(df)
    rows = {(r["primary_vendor"], r["primary_product"]): r for r in actions.collect()}

    assert rows[("microsoft", "windows")]["n_cves"] == 3
    assert rows[("apache", "httpd")]["n_cves"] == 2
    assert rows[("unknown", "unknown")]["n_cves"] == 1


def test_n_kev_counts_correctly(spark):
    """n_kev must equal the number of KEV CVEs in each group."""
    df = normalise_groups(_scores_df(spark))
    actions = build_remediation_actions(df)
    rows = {(r["primary_vendor"], r["primary_product"]): r for r in actions.collect()}

    assert rows[("microsoft", "windows")]["n_kev"] == 2
    assert rows[("apache", "httpd")]["n_kev"] == 0


def test_action_score_well_defined(spark):
    """action_score must be positive and finite for every row."""
    df = normalise_groups(_scores_df(spark))
    actions = build_remediation_actions(df)
    for row in actions.collect():
        assert row["action_score"] > 0
        assert math.isfinite(row["action_score"])


def test_ordering_descends_by_action_score(spark):
    """Rows must be sorted descending by action_score."""
    df = normalise_groups(_scores_df(spark))
    actions = build_remediation_actions(df)
    scores = [r["action_score"] for r in actions.collect()]
    assert scores == sorted(scores, reverse=True)


def test_top_cves_length_bounded(spark):
    """top_cves must contain at most `top_cves` entries (default 5)."""
    df = normalise_groups(_scores_df(spark))
    actions = build_remediation_actions(df, top_cves=2)
    for row in actions.collect():
        cves = row["top_cves"]
        assert cves is not None
        assert len(cves) <= 2


def test_top_cves_are_from_group(spark):
    """Every CVE in top_cves must belong to that vendor/product group."""
    df = normalise_groups(_scores_df(spark))
    actions = build_remediation_actions(df)

    # Build a lookup: cve_id → (vendor, product)
    original = {r["cve_id"]: (r["primary_vendor"], r["primary_product"])
                for r in df.collect()}

    for row in actions.collect():
        vendor, product = row["primary_vendor"], row["primary_product"]
        for cve_id in (row["top_cves"] or []):
            assert original[cve_id] == (vendor, product), (
                f"CVE {cve_id} does not belong to group ({vendor}, {product})"
            )


def test_effort_proxy_formula(spark):
    """effort_proxy must equal log(1 + n_cves) for every row."""
    df = normalise_groups(_scores_df(spark))
    actions = build_remediation_actions(df)
    for row in actions.collect():
        expected = math.log1p(row["n_cves"])
        assert abs(row["effort_proxy"] - expected) < 1e-6