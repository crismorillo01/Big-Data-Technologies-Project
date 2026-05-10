"""Tests for src/ingestion/ingest_epss.py — column rename, type casts, score_date."""

from __future__ import annotations

import datetime as dt

from src.ingestion.ingest_epss import clean_epss


def _raw_epss_df(spark):
    rows = [
        ("CVE-2024-0001", "0.5",  "0.95"),
        ("cve-2024-0002", "0.01", "0.10"),
        ("CVE-2024-0003", None,   "0.50"),
    ]
    return spark.createDataFrame(rows, ["cve", "epss", "percentile"])


def test_clean_epss_renames_and_uppercases(spark):
    out = clean_epss(_raw_epss_df(spark), "2026-05-10").orderBy("cve_id").collect()
    cves = [r["cve_id"] for r in out]
    assert cves == ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"]


def test_clean_epss_casts_doubles(spark):
    out = clean_epss(_raw_epss_df(spark), "2026-05-10").orderBy("cve_id").collect()
    assert out[0]["epss_score"] == 0.5
    assert out[0]["epss_percentile"] == 0.95
    # Null EPSS scores stay null after the cast (we don't impute at this stage)
    assert out[2]["epss_score"] is None


def test_clean_epss_attaches_score_date(spark):
    out = clean_epss(_raw_epss_df(spark), "2026-05-10").orderBy("cve_id").collect()
    assert out[0]["score_date"] == dt.date(2026, 5, 10)


def test_clean_epss_keeps_only_expected_columns(spark):
    df = clean_epss(_raw_epss_df(spark), "2026-05-10")
    assert set(df.columns) == {"cve_id", "epss_score", "epss_percentile", "score_date"}
