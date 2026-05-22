"""Tests for src/ingestion/ingest_nvd.py — the heart of the ingestion logic.

The transform fans out a deeply-nested NVD 2.0 JSON into a flat silver
schema. We test it end-to-end by writing a tiny JSON fixture matching
the real NVD shape, loading it through Spark, and asserting on the
extracted columns. This catches schema regressions (the most common
break in this code) without needing a full NVD download.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.ingestion.ingest_nvd import (
    filter_min_published_year,
    load_nvd_year,
    transform_nvd_year,
)


def _nvd_fixture() -> dict:
    """A 4-CVE NVD 2.0 fixture covering the interesting edge cases.

    - CVE-2024-0001: v4 + v3.1 + v3.0 + CPE + 2 weaknesses (multiple CWEs) + Exploit ref
                     -> tests the v4 > v3.1 precedence in the CVSS fallback chain
    - CVE-2024-0002: only v2 metric (tests v2 fallback)
    - CVE-2024-0003: no metrics at all (cvss_* must all be null)
    - CVE-2024-0004: weakness with NVD-CWE-Other (must be filtered out)

    Note: every CVSS metric type (v40, v31, v30, v2) appears at least once
    across the fixture so Spark's JSON schema inference produces all four
    nested struct fields. Without that, the transform's references to
    ``metrics.cvssMetricVxx`` would fail with FIELD_NOT_FOUND.
    """
    return {
        "vulnerabilities": [
            {"cve": {
                "id": "CVE-2024-0001",
                "published": "2024-01-15T10:00:00.000",
                "lastModified": "2024-02-01T12:00:00.000",
                "descriptions": [{"lang": "en", "value": "RCE via crafted input"}],
                "weaknesses": [
                    {"description": [{"lang": "en", "value": "CWE-78"}, {"lang": "en", "value": "CWE-89"}]},
                    {"description": [{"lang": "en", "value": "CWE-89"}]},  # duplicate, must dedup
                ],
                "metrics": {
                    # v4 must win over v3.1 / v3.0 in the fallback chain
                    "cvssMetricV40": [{"cvssData": {"baseScore": 9.9, "baseSeverity": "CRITICAL"}}],
                    "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
                    "cvssMetricV30": [{"cvssData": {"baseScore": 9.7, "baseSeverity": "CRITICAL"}}],
                },
                "configurations": [
                    {"nodes": [{"cpeMatch": [
                        {"criteria": "cpe:2.3:a:acme:product1:1.0:*:*:*:*:*:*:*"},
                        {"criteria": "cpe:2.3:a:acme:product1:1.1:*:*:*:*:*:*:*"},
                    ]}]},
                    {"nodes": [{"cpeMatch": [
                        {"criteria": "cpe:2.3:a:other:product2:2.0:*:*:*:*:*:*:*"},
                    ]}]},
                ],
                "references": [
                    {"url": "https://example.com/exploit", "tags": ["Exploit", "Third Party Advisory"]},
                    {"url": "https://example.com/patch",   "tags": ["Patch"]},
                ],
            }},
            {"cve": {
                "id": " cve-2024-0002 ",  # whitespace + lowercase to test trim+upper
                "published": "2024-03-01T00:00:00.000",
                "lastModified": "2024-03-02T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "v2-only CVE"}],
                "weaknesses": [],
                "metrics": {
                    "cvssMetricV2": [{"cvssData": {"baseScore": 7.5}, "baseSeverity": "HIGH"}],
                },
                "configurations": [],
                "references": [],
            }},
            {"cve": {
                "id": "CVE-2024-0003",
                "published": "2024-04-01T00:00:00.000",
                "lastModified": "2024-04-01T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "No metrics"}],
                "weaknesses": [],
                "metrics": {},
                "configurations": [],
                "references": [],
            }},
            {"cve": {
                "id": "CVE-2024-0004",
                "published": "2024-05-01T00:00:00.000",
                "lastModified": "2024-05-01T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "Has NVD-CWE-Other"}],
                "weaknesses": [
                    {"description": [{"lang": "en", "value": "NVD-CWE-Other"}]},
                    {"description": [{"lang": "en", "value": "CWE-200"}]},
                ],
                "metrics": {},
                "configurations": [],
                "references": [],
            }},
        ]
    }


@pytest.fixture
def nvd_silver(spark, tmp_path: Path):
    """Write the fixture as a multiline JSON, run the full transform, return rows by id."""
    json_path = tmp_path / "nvdcve-2.0-2024.json"
    json_path.write_text(json.dumps(_nvd_fixture()))

    df_raw = load_nvd_year(spark, json_path)
    df_silver = transform_nvd_year(df_raw, year=2024)
    rows = df_silver.collect()
    return {r["cve_id"]: r.asDict() for r in rows}


def test_cve_ids_are_normalized(nvd_silver):
    assert set(nvd_silver.keys()) == {
        "CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003", "CVE-2024-0004",
    }


def test_cvss_fallback_chain(nvd_silver):
    # v4 wins when v4, v3.1 and v3.0 are all present (precedence: v4 > v3.1 > v3.0 > v2)
    assert nvd_silver["CVE-2024-0001"]["cvss_score"] == 9.9
    assert nvd_silver["CVE-2024-0001"]["cvss_severity"] == "CRITICAL"
    assert nvd_silver["CVE-2024-0001"]["cvss_version"] == "v4.0"

    # v2 fallback (no v3+ metric)
    assert nvd_silver["CVE-2024-0002"]["cvss_score"] == 7.5
    assert nvd_silver["CVE-2024-0002"]["cvss_severity"] == "HIGH"
    assert nvd_silver["CVE-2024-0002"]["cvss_version"] == "v2"

    # no metric at all
    assert nvd_silver["CVE-2024-0003"]["cvss_score"] is None
    assert nvd_silver["CVE-2024-0003"]["cvss_version"] is None


def test_cwe_extraction_dedups_and_filters_non_cwe(nvd_silver):
    cwes_001 = sorted(nvd_silver["CVE-2024-0001"]["cwes"])
    assert cwes_001 == ["CWE-78", "CWE-89"]  # dedup of CWE-89

    # NVD-CWE-Other must be filtered out
    cwes_004 = nvd_silver["CVE-2024-0004"]["cwes"]
    assert cwes_004 == ["CWE-200"]


def test_cpe_arrays_are_distinct(nvd_silver):
    row = nvd_silver["CVE-2024-0001"]
    assert sorted(row["cpe_vendors"]) == ["acme", "other"]
    assert sorted(row["cpe_products"]) == ["product1", "product2"]


def test_cpe_arrays_handle_missing_configurations(nvd_silver):
    row = nvd_silver["CVE-2024-0003"]
    # No configurations -> empty array (or None, depending on Spark; either is fine
    # downstream because element_at + coalesce handles both).
    assert row["cpe_vendors"] in (None, [])


def test_reference_count_and_exploit_flag(nvd_silver):
    assert nvd_silver["CVE-2024-0001"]["reference_count"] == 2
    assert nvd_silver["CVE-2024-0001"]["has_exploit_reference"] is True

    # No references at all
    assert nvd_silver["CVE-2024-0002"]["reference_count"] == 0
    assert nvd_silver["CVE-2024-0002"]["has_exploit_reference"] is False


def test_published_year_is_derived(nvd_silver):
    assert nvd_silver["CVE-2024-0001"]["published_year"] == 2024
    assert nvd_silver["CVE-2024-0002"]["published_year"] == 2024


def test_min_published_year_filter_matches_modified_window(spark):
    df = spark.createDataFrame(
        [
            ("CVE-2014-0001", 2014),
            ("CVE-2015-0001", 2015),
            ("CVE-2024-0001", 2024),
        ],
        ["cve_id", "published_year"],
    )

    rows = filter_min_published_year(df, min_year=2015).collect()

    assert {row["cve_id"] for row in rows} == {"CVE-2015-0001", "CVE-2024-0001"}
