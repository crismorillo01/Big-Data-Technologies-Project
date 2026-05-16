"""DuckDB helpers for the Streamlit app and analysis notebooks.

Every query the app makes goes through this module.  The helpers:
- register no persistent tables; they use DuckDB's `read_parquet()` glob
  to scan the gold-layer Parquet files with predicate pushdown.
- return plain ``pandas.DataFrame`` objects ready for Streamlit / Plotly.
- use parameterised SQL (`?` placeholders) so no f-string SQL injection is
  possible.

All gold-layer paths come from ``src.config``. No raw path strings live here.
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
    GOLD_MASTER_DIR,
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
    """Return a fresh in-memory DuckDB connection.

    Each connection is independent; we create one per query rather than
    holding a long-lived singleton so the app is safe to run in Streamlit's
    threaded/process model.
    """
    return duckdb.connect(database=":memory:")


# ---------------------------------------------------------------------------
# Low-level helper
# ---------------------------------------------------------------------------

def query_parquet(sql: str, params: list[Any] | None = None) -> pd.DataFrame:
    con = get_connection()
    try:
        if params:
            result = con.execute(sql, params)
        else:
            result = con.execute(sql)
        return result.df()
    except Exception as e:
        _log.warning("DuckDB query failed: %s", e)
        return pd.DataFrame()  # return empty instead of crashing the app
    finally:
        con.close()


def _glob(path: Path) -> str:
    """Return a DuckDB-compatible glob string for all parquet files under *path*."""
    return str(path / "**" / "*.parquet")


# ---------------------------------------------------------------------------
# Pre-defined view helpers (used by Streamlit pages)
# ---------------------------------------------------------------------------

def top_n_vulnerabilities(
    n=50, min_priority=0.0, only_kev=False, vendor=None, snapshot_date=None
) -> pd.DataFrame:
    glob = _glob(GOLD_VULN_SCORES_FINAL_DIR)
    # Fall back to base scores if final scores don't exist yet
    if not any(GOLD_VULN_SCORES_FINAL_DIR.rglob("*.parquet")):
        _log.warning("vulnerability_scores_final not found, trying vulnerability_scores")
        from src.config import GOLD_VULN_SCORES_DIR
        glob = _glob(GOLD_VULN_SCORES_DIR)
        if not any(GOLD_VULN_SCORES_DIR.rglob("*.parquet")):
            return pd.DataFrame()

    conditions = ["priority_score >= ?"] if "scores_final" not in glob else ["priority_score_final >= ?"]
    params: list[Any] = [min_priority]
    if only_kev:
        conditions.append("is_kev = 1")
    if vendor:
        conditions.append("primary_vendor = ?")
        params.append(vendor)
    if snapshot_date:
        conditions.append("snapshot_date = ?")
        params.append(snapshot_date)

    where_clause = " AND ".join(conditions)
    score_col = "priority_score_final" if "scores_final" in glob else "priority_score"
    sql = f"""
        SELECT *
        FROM read_parquet('{glob}', hive_partitioning=true)
        WHERE {where_clause}
        ORDER BY {score_col} DESC
        LIMIT {int(n)}
    """
    return query_parquet(sql, params if params else None)

def cluster_overview(snapshot_date: str | None = None) -> pd.DataFrame:
    """Return cluster risk summary rows, optionally restricted to one snapshot."""
    glob = _glob(GOLD_CLUSTER_RISK_SUMMARY_DIR)
    conditions = []
    params: list[Any] = []
    if snapshot_date:
        conditions.append("snapshot_date = ?")
        params.append(snapshot_date)
    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    sql = f"""
        SELECT *
        FROM read_parquet('{glob}', hive_partitioning=true, union_by_name=true)
        {where_clause}
        ORDER BY kev_density DESC
    """
    return query_parquet(sql, params if params else None)


def strategy_comparison(snapshot_date: str | None = None) -> pd.DataFrame:
    """Return the strategy comparison table, optionally restricted to one snapshot."""
    glob = _glob(GOLD_STRATEGY_COMPARISON_DIR)
    conditions = []
    params: list[Any] = []
    if snapshot_date:
        conditions.append("snapshot_date = ?")
        params.append(snapshot_date)
    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    sql = f"""
        SELECT *
        FROM read_parquet('{glob}', hive_partitioning=true, union_by_name=true)
        {where_clause}
        ORDER BY kev_coverage DESC
    """
    return query_parquet(sql, params if params else None)


def remediation_actions(top_n: int = 50, snapshot_date: str | None = None) -> pd.DataFrame:
    """Return the top-N remediation actions ordered by action_score.

    Parameters
    ----------
    top_n         : Maximum rows to return.
    snapshot_date : If set, restrict to that snapshot partition.
    """
    glob = _glob(GOLD_REMEDIATION_ACTIONS_DIR)

    if snapshot_date:
        sql = f"""
            SELECT *
            FROM read_parquet('{glob}', hive_partitioning=true)
            WHERE snapshot_date = ?
            ORDER BY action_score DESC
            LIMIT {int(top_n)}
        """
        return query_parquet(sql, [snapshot_date])

    sql = f"""
        SELECT *
        FROM read_parquet('{glob}', hive_partitioning=true)
        ORDER BY action_score DESC
        LIMIT {int(top_n)}
    """
    return query_parquet(sql)


def data_quality_latest(snapshot_date: str | None = None) -> pd.DataFrame:
    """Return data-quality summary metrics, optionally restricted to one snapshot."""
    summary_dir = GOLD_DATA_QUALITY_DIR / "summary"
    glob = _glob(summary_dir)
    conditions = []
    params: list[Any] = []
    if snapshot_date:
        conditions.append("snapshot_date = ?")
        params.append(snapshot_date)
    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    sql = f"""
        SELECT *
        FROM read_parquet('{glob}', hive_partitioning=true, union_by_name=true)
        {where_clause}
        ORDER BY snapshot_date DESC
    """
    return query_parquet(sql, params if params else None)


def simulation_timeseries(snapshot_date: str | None = None) -> pd.DataFrame:
    """Return the multi-day simulation timeseries."""
    import pandas as pd
    # Try all parquet files under the directory
    base = GOLD_SIMULATION_TIMESERIES_DIR
    parquet_files = list(base.rglob("*.parquet"))
    if not parquet_files:
        return pd.DataFrame()
    try:
        dfs = [pd.read_parquet(f) for f in parquet_files]
        df = pd.concat(dfs, ignore_index=True)
        if snapshot_date and "snapshot_date" in df.columns:
            df = df[df["snapshot_date"].astype(str) == snapshot_date]
        return df.sort_values(["strategy", "day"]) if "strategy" in df.columns else df
    except Exception as e:
        _log.warning("Could not read simulation timeseries: %s", e)
        return pd.DataFrame()


def available_snapshots() -> list[str]:
    """Return all snapshot dates from the gold folder directly (no DuckDB needed)."""
    available = sorted([
        p.name.replace("snapshot_date=", "")
        for p in GOLD_VULN_SCORES_FINAL_DIR.iterdir()
        if p.is_dir() and p.name.startswith("snapshot_date=")
    ], reverse=True) if GOLD_VULN_SCORES_FINAL_DIR.exists() else []
    return available
