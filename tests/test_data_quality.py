"""Tests for src/processing/data_quality.py."""

from __future__ import annotations

import datetime as dt

from src.processing.data_quality import (
    compute_kev_by_year,
    compute_severity_distribution,
    compute_summary_metrics,
)

SNAPSHOT = "2026-05-12"


def _master_df(spark):
    rows = [
        # cve_id, cvss_score, epss_score, cwes, cpe_vendors, is_kev, kev_date_added, cvss_severity, snapshot_date
        ("CVE-2024-0001", 9.8,  0.95, ["CWE-78"],  ["acme"], 1, dt.date(2024, 1, 1), "CRITICAL", dt.date(2026, 5, 12)),
        ("CVE-2024-0002", 7.5,  0.0,  ["CWE-287"], [],       1, dt.date(2023, 3, 1), "HIGH",     dt.date(2026, 5, 12)),
        ("CVE-2024-0003", None, 0.72, [],           ["corp"], 0, None,               "MEDIUM",   dt.date(2026, 5, 12)),
        ("CVE-2024-0004", 4.0,  0.0,  None,         None,    0, None,               "LOW",      dt.date(2026, 5, 12)),
    ]
    cols = [
        "cve_id", "cvss_score", "epss_score", "cwes", "cpe_vendors",
        "is_kev", "kev_date_added", "cvss_severity", "snapshot_date",
    ]
    return spark.createDataFrame(rows, cols)


def test_kev_count_correct(spark):
    result = compute_summary_metrics(_master_df(spark), SNAPSHOT).collect()[0]
    assert result["kev_count"] == 2


def test_pct_null_cvss(spark):
    result = compute_summary_metrics(_master_df(spark), SNAPSHOT).collect()[0]
    assert abs(result["pct_null_cvss"] - 25.0) < 0.01


def test_nvd_epss_intersection(spark):
    result = compute_summary_metrics(_master_df(spark), SNAPSHOT).collect()[0]
    # epss_score > 0: CVE-0001 (0.95) and CVE-0003 (0.72)
    assert result["nvd_epss_intersection"] == 2


def test_nvd_kev_intersection(spark):
    result = compute_summary_metrics(_master_df(spark), SNAPSHOT).collect()[0]
    assert result["nvd_kev_intersection"] == 2


def test_nvd_kev_epss_intersection(spark):
    result = compute_summary_metrics(_master_df(spark), SNAPSHOT).collect()[0]
    # KEV AND epss > 0: only CVE-0001
    assert result["nvd_kev_epss_intersection"] == 1


def test_severity_distribution_counts(spark):
    rows = {
        r["cvss_severity"]: r["cve_count"]
        for r in compute_severity_distribution(_master_df(spark), SNAPSHOT).collect()
    }
    assert rows["CRITICAL"] == 1
    assert rows["HIGH"] == 1


def test_kev_by_year_counts(spark):
    rows = {
        r["kev_year"]: r["kev_count"]
        for r in compute_kev_by_year(_master_df(spark), SNAPSHOT).collect()
    }
    assert rows[2024] == 1
    assert rows[2023] == 1
