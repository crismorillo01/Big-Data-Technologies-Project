"""Tests for src/processing/join_master.py — the most schema-sensitive module.

Tests cover:
- ``prepare_kev`` and ``prepare_epss`` rename / select correctly.
- ``build_master_dataset`` left-joins and applies the right defaults.
- ``primary_vendor`` / ``primary_product`` fall back to KEV when CPE is missing.
- ``snapshot_date`` is a ``date`` column stamped from the parameter, not from the data.
"""

from __future__ import annotations

import datetime as dt

from src.processing.join_master import (
    build_master_dataset,
    prepare_epss,
    prepare_kev,
)


def _silver_nvd_df(spark):
    """Three CVEs with varying CPE coverage."""
    rows = [
        # CVE has full CPE arrays
        ("CVE-2024-0001", dt.datetime(2024, 1, 15), dt.datetime(2024, 2, 1),
         "rce", ["CWE-78"], 9.8, "CRITICAL", "v3.1",
         ["acme"], ["productA"], ["1.0"], 2, True, 2024),
        # CVE has NO CPE — vendor/product must fall back to KEV
        ("CVE-2024-0002", dt.datetime(2024, 3, 1), dt.datetime(2024, 3, 2),
         "auth", ["CWE-287"], 7.5, "HIGH", "v3.1",
         [], [], [], 0, False, 2024),
        # CVE not in KEV and not in EPSS — must keep defaults
        ("CVE-2024-0003", dt.datetime(2024, 4, 1), dt.datetime(2024, 4, 1),
         "info disclosure", ["CWE-200"], 4.0, "MEDIUM", "v3.1",
         ["thirdparty"], ["productC"], ["3.0"], 1, False, 2024),
    ]
    cols = [
        "cve_id", "published", "last_modified", "description", "cwes",
        "cvss_score", "cvss_severity", "cvss_version",
        "cpe_vendors", "cpe_products", "cpe_versions",
        "reference_count", "has_exploit_reference", "published_year",
    ]
    return spark.createDataFrame(rows, cols)


def _silver_kev_df(spark):
    """Two of the three CVEs are in KEV; CVE-2024-0003 is not."""
    rows = [
        ("CVE-2024-0001", "VendorA", "ProductA", "RCE",
         dt.date(2024, 1, 20), "short", "patch", "Known", True),
        ("CVE-2024-0002", "VendorB", "ProductB", "Auth bypass",
         dt.date(2024, 3, 5), "short", "patch", "Unknown", False),
    ]
    cols = [
        "cve_id", "vendor_project", "product", "vulnerability_name",
        "kev_date_added", "short_description", "required_action",
        "known_ransomware_campaign_use", "is_ransomware",
    ]
    return spark.createDataFrame(rows, cols)


def _silver_epss_df(spark):
    """Two of the three CVEs are in EPSS; CVE-2024-0003 is not."""
    rows = [
        ("CVE-2024-0001", 0.95, 0.99, dt.date(2026, 5, 10)),
        ("CVE-2024-0002", 0.05, 0.50, dt.date(2026, 5, 10)),
    ]
    cols = ["cve_id", "epss_score", "epss_percentile", "score_date"]
    return spark.createDataFrame(rows, cols)


# ---------------------------------------------------------------------------
# prepare_*
# ---------------------------------------------------------------------------

def test_prepare_kev_renames_with_kev_prefix_and_adds_is_kev(spark):
    out = prepare_kev(_silver_kev_df(spark))
    assert "kev_vendor" in out.columns
    assert "kev_product" in out.columns
    assert "kev_vulnerability_name" in out.columns
    assert "vendor_project" not in out.columns  # original gone
    assert "product" not in out.columns
    rows = out.orderBy("cve_id").collect()
    assert all(r["is_kev"] == 1 for r in rows)


def test_prepare_epss_keeps_epss_score_date(spark):
    out = prepare_epss(_silver_epss_df(spark))
    assert "epss_score_date" in out.columns
    assert "score_date" not in out.columns


# ---------------------------------------------------------------------------
# build_master_dataset
# ---------------------------------------------------------------------------

def test_master_left_joins_all_nvd_rows(spark):
    master = build_master_dataset(
        _silver_nvd_df(spark), _silver_kev_df(spark), _silver_epss_df(spark),
        snapshot_date_str="2026-05-10",
    )
    rows = {r["cve_id"]: r for r in master.collect()}
    assert set(rows.keys()) == {"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"}


def test_master_defaults_for_missing_kev_and_epss(spark):
    master = build_master_dataset(
        _silver_nvd_df(spark), _silver_kev_df(spark), _silver_epss_df(spark),
        snapshot_date_str="2026-05-10",
    )
    rows = {r["cve_id"]: r for r in master.collect()}
    not_in_either = rows["CVE-2024-0003"]
    assert not_in_either["is_kev"] == 0
    assert not_in_either["is_ransomware"] is False
    assert not_in_either["epss_score"] == 0.0
    assert not_in_either["epss_percentile"] == 0.0


def test_primary_vendor_uses_cpe_first_then_falls_back_to_kev(spark):
    master = build_master_dataset(
        _silver_nvd_df(spark), _silver_kev_df(spark), _silver_epss_df(spark),
        snapshot_date_str="2026-05-10",
    )
    rows = {r["cve_id"]: r for r in master.collect()}
    # CVE-0001 has CPE -> primary_vendor is from NVD
    assert rows["CVE-2024-0001"]["primary_vendor"] == "acme"
    assert rows["CVE-2024-0001"]["primary_product"] == "productA"
    # CVE-0002 has no CPE but is in KEV -> falls back to KEV vendor/product
    assert rows["CVE-2024-0002"]["primary_vendor"] == "VendorB"
    assert rows["CVE-2024-0002"]["primary_product"] == "ProductB"
    # CVE-0003 has CPE and no KEV -> NVD CPE vendor wins
    assert rows["CVE-2024-0003"]["primary_vendor"] == "thirdparty"


def test_master_stamps_snapshot_date_from_parameter(spark):
    master = build_master_dataset(
        _silver_nvd_df(spark), _silver_kev_df(spark), _silver_epss_df(spark),
        snapshot_date_str="2026-05-10",
    )
    snapshots = {r["snapshot_date"] for r in master.collect()}
    assert snapshots == {dt.date(2026, 5, 10)}


def test_master_keeps_kev_fields_under_prefix(spark):
    master = build_master_dataset(
        _silver_nvd_df(spark), _silver_kev_df(spark), _silver_epss_df(spark),
        snapshot_date_str="2026-05-10",
    )
    cols = master.columns
    for c in ("kev_date_added", "kev_vendor", "kev_product",
              "kev_vulnerability_name", "kev_short_description",
              "kev_required_action", "is_ransomware",
              "epss_score_date", "primary_vendor", "primary_product"):
        assert c in cols, f"missing column: {c}"
