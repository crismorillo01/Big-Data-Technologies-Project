"""DuckDB helpers for the Streamlit app and analysis notebooks.

Every query the app makes goes through this module. The helpers:
- register no persistent tables; they use DuckDB's read_parquet() glob
  to scan the gold-layer Parquet files with predicate pushdown.
- return plain pandas.DataFrame objects ready for Streamlit / Plotly.
- use parameterised SQL (? placeholders) so no f-string SQL injection is possible.

All gold-layer paths come from src.config. No raw path strings live here.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import duckdb
import pandas as pd

from src.config import (
    GOLD_CLUSTER_RISK_SUMMARY_DIR,
    GOLD_CLUSTER_TOPICS_DIR,
    GOLD_DATA_QUALITY_DIR,
    GOLD_REMEDIATION_ACTIONS_DIR,
    GOLD_SIMULATION_TIMESERIES_DIR,
    GOLD_STRATEGY_COMPARISON_DIR,
    GOLD_VULN_SCORES_FINAL_DIR,
)

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------

def get_connection() -> duckdb.DuckDBPyConnection:
    """Return a fresh in-memory DuckDB connection."""
    return duckdb.connect(database=":memory:")


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def _glob(path: Path) -> str:
    """Return a DuckDB-compatible glob for all parquet files under path."""
    return str(path / "**" / "*.parquet")


def _latest_snapshot(base_dir: Path) -> str | None:
    """Return the most recent snapshot_date partition name."""
    if not base_dir.exists():
        return None
    available = sorted([
        p.name.replace("snapshot_date=", "")
        for p in base_dir.iterdir()
        if p.is_dir() and p.name.startswith("snapshot_date=")
    ], reverse=True)
    return available[0] if available else None


def _resolve_snapshot(base_dir: Path, requested: str | None) -> str | None:
    """Return requested date if available, else latest, else None."""
    latest = _latest_snapshot(base_dir)
    if not latest:
        return None
    if requested and requested[:10] == latest:
        return latest
    # Check if requested date exists as a partition
    if requested:
        req = requested[:10]
        partition = base_dir / f"snapshot_date={req}"
        if partition.exists():
            return req
    return latest


def query_parquet(sql: str, params: list[Any] | None = None) -> pd.DataFrame:
    """Execute sql and return a DataFrame. Returns empty DataFrame on error."""
    con = get_connection()
    try:
        result = con.execute(sql, params) if params else con.execute(sql)
        return result.df()
    except Exception as e:
        _log.warning("DuckDB query failed: %s", e)
        return pd.DataFrame()
    finally:
        con.close()


# ---------------------------------------------------------------------------
# Overview stats — used by Overview KPIs
# ---------------------------------------------------------------------------

def overview_stats(snapshot_date: str | None = None) -> pd.DataFrame:
    """Return all CVEs for KPI computation (cve_id, is_kev, epss_score,
    priority_level_final, cvss_severity) for the given snapshot.

    Only loads the columns needed for KPIs — no full row scan.
    """
    actual = _resolve_snapshot(GOLD_VULN_SCORES_FINAL_DIR, snapshot_date)
    if not actual:
        return pd.DataFrame()

    partition = GOLD_VULN_SCORES_FINAL_DIR / f"snapshot_date={actual}"
    glob = str(partition / "*.parquet")

    sql = f"""
        SELECT
            cve_id,
            is_kev,
            epss_score,
            priority_level_final,
            cvss_severity
        FROM read_parquet('{glob}', union_by_name=true)
    """
    return query_parquet(sql)


# ---------------------------------------------------------------------------
# Top N vulnerabilities — used by Vulnerability Explorer
# ---------------------------------------------------------------------------

def top_n_vulnerabilities(
    n: int = 50,
    priority_level: str | None = None,
    only_kev: bool = False,
    vendor: str | None = None,
    snapshot_date: str | None = None,
) -> pd.DataFrame:
    """Return the top-N scored vulnerabilities."""
    actual = _resolve_snapshot(GOLD_VULN_SCORES_FINAL_DIR, snapshot_date)
    if not actual:
        return pd.DataFrame()

    partition = GOLD_VULN_SCORES_FINAL_DIR / f"snapshot_date={actual}"
    glob = str(partition / "*.parquet")

    conditions: list[str] = []
    params: list[Any] = []

    if priority_level and priority_level != "All":
        conditions.append("priority_level_final = ?")
        params.append(priority_level)
    if only_kev:
        conditions.append("is_kev = 1")
    if vendor:
        conditions.append("primary_vendor ILIKE ?")
        params.append(f"%{vendor}%")

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    sql = f"""
        SELECT *
        FROM read_parquet('{glob}', union_by_name=true)
        {where_clause}
        ORDER BY priority_score_final DESC
        LIMIT {int(n)}
    """
    return query_parquet(sql, params)


# ---------------------------------------------------------------------------
# Cluster overview
# ---------------------------------------------------------------------------

def cluster_overview(snapshot_date: str | None = None) -> pd.DataFrame:
    """Return cluster risk summary for one snapshot, optionally joined with topics."""
    actual = _resolve_snapshot(GOLD_CLUSTER_RISK_SUMMARY_DIR, snapshot_date)
    if not actual:
        return pd.DataFrame()

    risk_glob = _glob(GOLD_CLUSTER_RISK_SUMMARY_DIR)

    # Try joining with topics if available
    topics_glob = _glob(GOLD_CLUSTER_TOPICS_DIR)
    try:
        sql = f"""
            SELECT r.*,
                   t.top_keywords,
                   t.top_vendors AS topic_vendors,
                   t.top_cwes
            FROM read_parquet('{risk_glob}', hive_partitioning=true, union_by_name=true) r
            LEFT JOIN read_parquet('{topics_glob}', hive_partitioning=true, union_by_name=true) t
                ON r.cluster_id = t.cluster_id
               AND CAST(r.snapshot_date AS VARCHAR) = CAST(t.snapshot_date AS VARCHAR)
            WHERE CAST(r.snapshot_date AS VARCHAR) LIKE ?
            ORDER BY r.kev_density DESC, r.cluster_size DESC
        """
        df = query_parquet(sql, [f"{actual}%"])
        if not df.empty:
            return df
    except Exception:
        pass

    # Fallback: just risk summary
    sql = f"""
        SELECT *
        FROM read_parquet('{risk_glob}', hive_partitioning=true, union_by_name=true)
        WHERE CAST(snapshot_date AS VARCHAR) LIKE ?
          AND cluster_size > 0
        ORDER BY kev_density DESC, cluster_size DESC
    """
    return query_parquet(sql, [f"{actual}%"])


# ---------------------------------------------------------------------------
# Strategy comparison
# ---------------------------------------------------------------------------

def strategy_comparison(snapshot_date: str | None = None) -> pd.DataFrame:
    """Return the strategy comparison table for one snapshot."""
    actual = _resolve_snapshot(GOLD_STRATEGY_COMPARISON_DIR, snapshot_date)
    if not actual:
        return pd.DataFrame()

    glob = _glob(GOLD_STRATEGY_COMPARISON_DIR)
    sql = f"""
        SELECT *
        FROM read_parquet('{glob}', hive_partitioning=true, union_by_name=true)
        WHERE CAST(snapshot_date AS VARCHAR) LIKE ?
        ORDER BY kev_coverage DESC
    """
    return query_parquet(sql, [f"{actual}%"])


# ---------------------------------------------------------------------------
# Remediation actions
# ---------------------------------------------------------------------------

def remediation_actions(
    top_n: int = 50,
    snapshot_date: str | None = None,
) -> pd.DataFrame:
    """Return the top-N remediation actions ordered by action_score."""
    actual = _resolve_snapshot(GOLD_REMEDIATION_ACTIONS_DIR, snapshot_date)
    glob = _glob(GOLD_REMEDIATION_ACTIONS_DIR)

    if actual:
        sql = f"""
            SELECT *
            FROM read_parquet('{glob}', hive_partitioning=true, union_by_name=true)
            WHERE CAST(snapshot_date AS VARCHAR) LIKE '{actual}%'
            ORDER BY action_score DESC
            LIMIT {int(top_n)}
        """
    else:
        sql = f"""
            SELECT *
            FROM read_parquet('{glob}', union_by_name=true)
            ORDER BY action_score DESC
            LIMIT {int(top_n)}
        """
    return query_parquet(sql)


# ---------------------------------------------------------------------------
# Data quality
# ---------------------------------------------------------------------------

def data_quality_latest() -> pd.DataFrame:
    """Return the most recent data-quality summary metrics."""
    summary_dir = GOLD_DATA_QUALITY_DIR / "summary"
    if not summary_dir.exists():
        return pd.DataFrame()
    glob = str(summary_dir / "**" / "*.parquet")
    sql = f"""
        SELECT *
        FROM read_parquet('{glob}', union_by_name=true)
    """
    return query_parquet(sql)


# ---------------------------------------------------------------------------
# Simulation timeseries
# ---------------------------------------------------------------------------

def simulation_timeseries(snapshot_date: str | None = None) -> pd.DataFrame:
    """Return the multi-day simulation timeseries for all strategies."""
    glob = _glob(GOLD_SIMULATION_TIMESERIES_DIR)
    actual = _resolve_snapshot(GOLD_SIMULATION_TIMESERIES_DIR, snapshot_date)

    if actual:
        sql = f"""
            SELECT *
            FROM read_parquet('{glob}', union_by_name=true)
            WHERE CAST(snapshot_date AS VARCHAR) LIKE '{actual}%'
            ORDER BY strategy, day
        """
    else:
        sql = f"""
            SELECT *
            FROM read_parquet('{glob}', union_by_name=true)
            ORDER BY strategy, day
        """
    return query_parquet(sql)


# ---------------------------------------------------------------------------
# Available snapshots
# ---------------------------------------------------------------------------

def available_snapshots() -> list[str]:
    """Return all snapshot_date values from folder names — always up to date."""
    if not GOLD_VULN_SCORES_FINAL_DIR.exists():
        return []
    return sorted([
        p.name.replace("snapshot_date=", "")
        for p in GOLD_VULN_SCORES_FINAL_DIR.iterdir()
        if p.is_dir() and p.name.startswith("snapshot_date=")
    ], reverse=True)
