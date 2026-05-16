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

def cluster_overview() -> pd.DataFrame:
    import pandas as pd
    base = GOLD_CLUSTER_RISK_SUMMARY_DIR
    parquet_files = list(base.rglob("*.parquet"))
    if not parquet_files:
        return pd.DataFrame()
    try:
        dfs = [pd.read_parquet(f) for f in parquet_files]
        return pd.concat(dfs, ignore_index=True).sort_values("kev_density", ascending=False)
    except Exception as e:
        _log.warning("cluster_overview failed: %s", e)
        return pd.DataFrame()


def strategy_comparison() -> pd.DataFrame:
    """Return the strategy comparison table."""
    # Try hive-partitioned first, fall back to flat
    glob = _glob(GOLD_STRATEGY_COMPARISON_DIR)
    try:
        sql = f"SELECT * FROM read_parquet('{glob}', union_by_name=true) ORDER BY kev_coverage DESC"
        df = query_parquet(sql)
        if df.empty:
            raise ValueError("empty")
        return df
    except Exception:
        # Try reading the flat file directly
        flat = str(GOLD_STRATEGY_COMPARISON_DIR / "part-00000.parquet")
        try:
            import pandas as pd
            return pd.read_parquet(flat)
        except Exception:
            return pd.DataFrame()


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


def data_quality_latest() -> pd.DataFrame:
    """Return the most recent data-quality summary metrics."""
    import pandas as pd

    # Read from the summary subfolder which has the main metrics
    summary_dir = GOLD_DATA_QUALITY_DIR / "summary"
    if not summary_dir.exists():
        return pd.DataFrame()

    files = list(summary_dir.rglob("*.parquet"))
    if not files:
        return pd.DataFrame()

    try:
        dfs = [pd.read_parquet(f) for f in files]
        return pd.concat(dfs, ignore_index=True)
    except Exception as e:
        _log.warning("data_quality_latest failed: %s", e)
        return pd.DataFrame()


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