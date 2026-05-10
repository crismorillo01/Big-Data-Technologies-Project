"""Tests for src/ingestion/ingest_kev.py — column rename, date typing, ransomware flag."""

from __future__ import annotations

import datetime as dt

from src.ingestion.ingest_kev import transform_kev


def _raw_kev_df(spark):
    """Build a tiny in-memory raw KEV-shaped DataFrame."""
    rows = [
        # cveID, vendor, product, name, dateAdded, short_desc, action, ransomware
        ("CVE-2024-0001", "VendorA", "ProdA", "RCE in ProdA", "2024-01-15", "short", "patch", "Known"),
        ("cve-2024-0002", "VendorB", "ProdB", "XSS",          "2024-02-20", "short", "patch", "Unknown"),
        ("CVE-2024-0003", "VendorC", "ProdC", "auth bypass",   "2024-03-10", "short", "patch", None),
    ]
    cols = [
        "cveID", "vendorProject", "product", "vulnerabilityName",
        "dateAdded", "shortDescription", "requiredAction",
        "knownRansomwareCampaignUse",
    ]
    return spark.createDataFrame(rows, cols)


def test_transform_kev_renames_columns_and_uppercases_cve_id(spark):
    out = transform_kev(_raw_kev_df(spark)).orderBy("cve_id").collect()
    assert {r["cve_id"] for r in out} == {"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"}
    # Original snake_case-equivalent columns are renamed correctly
    expected_cols = {
        "cve_id", "vendor_project", "product", "vulnerability_name",
        "kev_date_added", "short_description", "required_action",
        "known_ransomware_campaign_use", "is_ransomware",
    }
    assert set(transform_kev(_raw_kev_df(spark)).columns) == expected_cols


def test_transform_kev_casts_date_to_date_type(spark):
    out = transform_kev(_raw_kev_df(spark)).orderBy("cve_id").collect()
    assert out[0]["kev_date_added"] == dt.date(2024, 1, 15)
    assert isinstance(out[0]["kev_date_added"], dt.date)


def test_transform_kev_is_ransomware_flag(spark):
    """Only exactly 'Known' (case-insensitive) flips is_ransomware to True."""
    out = transform_kev(_raw_kev_df(spark)).orderBy("cve_id").collect()
    flags = {r["cve_id"]: r["is_ransomware"] for r in out}
    assert flags == {
        "CVE-2024-0001": True,    # "Known"
        "CVE-2024-0002": False,   # "Unknown"
        "CVE-2024-0003": False,   # null
    }
