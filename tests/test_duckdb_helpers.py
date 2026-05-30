"""Tests for Streamlit DuckDB helper queries."""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from src.utils import duckdb_helpers


pytest.importorskip("pyarrow")


def _write_snapshot(base_dir: Path, snapshot_date: str, rows: list[dict]) -> None:
    partition = base_dir / f"snapshot_date={snapshot_date}"
    partition.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_parquet(partition / "part-00000.parquet", index=False)


def test_cluster_overview_filters_snapshot_before_joining_topics(monkeypatch, tmp_path):
    risk_dir = tmp_path / "cluster_risk_summary"
    topics_dir = tmp_path / "cluster_topics"

    _write_snapshot(
        risk_dir,
        "2026-05-19",
        [
            {
                "cluster_id": 0,
                "cluster_size": 10,
                "kev_density": 0.1,
                "n_kev": 1,
                "avg_priority_final": 0.4,
                "avg_cvss": 6.0,
                "avg_epss": 0.1,
                "max_epss": 0.2,
            },
            {
                "cluster_id": 1,
                "cluster_size": 20,
                "kev_density": 0.2,
                "n_kev": 4,
                "avg_priority_final": 0.5,
                "avg_cvss": 7.0,
                "avg_epss": 0.2,
                "max_epss": 0.3,
            },
        ],
    )
    _write_snapshot(
        risk_dir,
        "2026-05-20",
        [
            {
                "cluster_id": 0,
                "cluster_size": 30,
                "kev_density": 0.3,
                "n_kev": 9,
                "avg_priority_final": 0.6,
                "avg_cvss": 8.0,
                "avg_epss": 0.3,
                "max_epss": 0.4,
            },
            {
                "cluster_id": 1,
                "cluster_size": 40,
                "kev_density": 0.4,
                "n_kev": 16,
                "avg_priority_final": 0.7,
                "avg_cvss": 9.0,
                "avg_epss": 0.4,
                "max_epss": 0.5,
            },
        ],
    )
    _write_snapshot(
        topics_dir,
        "2026-05-19",
        [
            {"cluster_id": 0, "top_keywords": "old-zero", "top_vendors": "old", "top_cwes": "CWE-1"},
            {"cluster_id": 1, "top_keywords": "old-one", "top_vendors": "old", "top_cwes": "CWE-2"},
        ],
    )
    _write_snapshot(
        topics_dir,
        "2026-05-20",
        [
            {"cluster_id": 0, "top_keywords": "new-zero", "top_vendors": "new", "top_cwes": "CWE-3"},
            {"cluster_id": 1, "top_keywords": "new-one", "top_vendors": "new", "top_cwes": "CWE-4"},
        ],
    )

    monkeypatch.setattr(duckdb_helpers, "GOLD_CLUSTER_RISK_SUMMARY_DIR", risk_dir)
    monkeypatch.setattr(duckdb_helpers, "GOLD_CLUSTER_TOPICS_DIR", topics_dir)

    result = duckdb_helpers.cluster_overview("2026-05-20")

    assert len(result) == 2
    assert set(result["cluster_id"]) == {0, 1}
    assert set(result["top_keywords"]) == {"new-zero", "new-one"}
    assert set(result["cluster_size"]) == {30, 40}


def test_top_n_vulnerabilities_filters_exact_priority_level(monkeypatch, tmp_path):
    scored_dir = tmp_path / "vulnerability_scores_final"
    _write_snapshot(
        scored_dir,
        "2026-05-20",
        [
            {
                "cve_id": "CVE-1",
                "priority_score_final": 0.95,
                "priority_level_final": "Critical",
                "is_kev": 0,
                "primary_vendor": "acme",
            },
            {
                "cve_id": "CVE-2",
                "priority_score_final": 0.75,
                "priority_level_final": "High",
                "is_kev": 0,
                "primary_vendor": "acme",
            },
            {
                "cve_id": "CVE-3",
                "priority_score_final": 0.45,
                "priority_level_final": "Medium",
                "is_kev": 0,
                "primary_vendor": "acme",
            },
        ],
    )

    monkeypatch.setattr(duckdb_helpers, "GOLD_VULN_SCORES_FINAL_DIR", scored_dir)

    result = duckdb_helpers.top_n_vulnerabilities(
        n=10,
        priority_level="High",
        snapshot_date="2026-05-20",
    )

    assert result["cve_id"].tolist() == ["CVE-2"]
    assert result["priority_level_final"].tolist() == ["High"]


def test_strategy_comparison_filters_snapshot(monkeypatch, tmp_path):
    strategy_dir = tmp_path / "strategy_comparison"
    _write_snapshot(
        strategy_dir,
        "2026-05-19",
        [
            {"strategy": "top_priority", "kev_coverage": 0.9},
            {"strategy": "high_epss", "kev_coverage": 0.4},
        ],
    )
    _write_snapshot(
        strategy_dir,
        "2026-05-20",
        [
            {"strategy": "top_priority", "kev_coverage": 0.7},
            {"strategy": "cluster_based", "kev_coverage": 0.3},
        ],
    )

    monkeypatch.setattr(duckdb_helpers, "GOLD_STRATEGY_COMPARISON_DIR", strategy_dir)

    result = duckdb_helpers.strategy_comparison("2026-05-20")

    assert result["strategy"].tolist() == ["top_priority", "cluster_based"]
    assert result["kev_coverage"].tolist() == [0.7, 0.3]


def test_data_quality_summary_filters_snapshot(monkeypatch, tmp_path):
    summary_dir = tmp_path / "data_quality" / "summary"
    _write_snapshot(
        summary_dir,
        "2026-05-19",
        [
            {
                "snapshot_date": "2026-05-19",
                "row_count": 10,
                "distinct_cve_count": 10,
                "pct_null_cvss": 5.0,
                "pct_null_epss": 10.0,
                "pct_null_cwes": 15.0,
                "pct_null_cpe": 20.0,
                "pct_epss_gt_07": 25.0,
                "pct_epss_gt_09": 30.0,
                "mean_epss": 0.11,
                "median_epss": 0.10,
                "kev_count": 2,
                "nvd_kev_intersection": 2,
                "nvd_epss_intersection": 4,
                "nvd_kev_epss_intersection": 1,
            },
        ],
    )
    _write_snapshot(
        summary_dir,
        "2026-05-20",
        [
            {
                "snapshot_date": "2026-05-20",
                "row_count": 12,
                "distinct_cve_count": 12,
                "pct_null_cvss": 1.0,
                "pct_null_epss": 2.0,
                "pct_null_cwes": 3.0,
                "pct_null_cpe": 4.0,
                "pct_epss_gt_07": 5.0,
                "pct_epss_gt_09": 6.0,
                "mean_epss": 0.21,
                "median_epss": 0.20,
                "kev_count": 3,
                "nvd_kev_intersection": 3,
                "nvd_epss_intersection": 5,
                "nvd_kev_epss_intersection": 2,
            },
        ],
    )

    monkeypatch.setattr(duckdb_helpers, "GOLD_DATA_QUALITY_DIR", tmp_path / "data_quality")

    result = duckdb_helpers.data_quality_summary("2026-05-20")

    assert result["snapshot_date"].astype(str).tolist() == ["2026-05-20"]
    assert result["kev_count"].tolist() == [3]
    assert result["pct_null_cvss"].tolist() == [1.0]


def test_remediation_recommendations_filters_strategy_and_snapshot(monkeypatch, tmp_path):
    recommendations_dir = tmp_path / "remediation_recommendations"
    _write_snapshot(
        recommendations_dir / "high_epss",
        "2026-05-19",
        [
            {
                "cve_id": "CVE-1",
                "priority_score_final": 0.60,
                "epss_score": 0.20,
                "is_kev": 0,
                "cvss_score": 6.0,
                "primary_vendor": "acme",
                "primary_product": "old",
            },
            {
                "cve_id": "CVE-2",
                "priority_score_final": 0.70,
                "epss_score": 0.80,
                "is_kev": 1,
                "cvss_score": 7.0,
                "primary_vendor": "acme",
                "primary_product": "old",
            },
        ],
    )
    _write_snapshot(
        recommendations_dir / "high_epss",
        "2026-05-20",
        [
            {
                "cve_id": "CVE-3",
                "priority_score_final": 0.90,
                "epss_score": 0.95,
                "is_kev": 1,
                "cvss_score": 8.0,
                "primary_vendor": "acme",
                "primary_product": "new",
            },
            {
                "cve_id": "CVE-4",
                "priority_score_final": 0.40,
                "epss_score": 0.10,
                "is_kev": 0,
                "cvss_score": 4.0,
                "primary_vendor": "acme",
                "primary_product": "new",
            },
        ],
    )

    monkeypatch.setattr(duckdb_helpers, "GOLD_REMEDIATION_RECOMMENDATIONS_DIR", recommendations_dir)

    result = duckdb_helpers.remediation_recommendations(
        "high_epss",
        top_n=1,
        snapshot_date="2026-05-20",
    )

    assert result["cve_id"].tolist() == ["CVE-3"]
    assert result["epss_score"].tolist() == [0.95]
