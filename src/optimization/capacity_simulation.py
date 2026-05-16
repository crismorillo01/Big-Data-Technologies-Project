"""Capacity simulation job — pure pandas/pyarrow, no Spark workers."""

from __future__ import annotations

import argparse
import logging
import math
import sys
from pathlib import Path

import pandas as pd
import pyarrow.parquet as pq
import pyarrow as pa

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.config import (
    DEFAULT_ARRIVAL_RATE,
    DEFAULT_DAILY_CAPACITY,
    DEFAULT_SIMULATION_DAYS,
    GOLD_CLUSTER_RISK_SUMMARY_DIR,
    GOLD_REMEDIATION_RECOMMENDATIONS_DIR,
    GOLD_SIMULATION_TIMESERIES_DIR,
    GOLD_STRATEGY_COMPARISON_DIR,
    GOLD_VULN_SCORES_FINAL_DIR,
    configure_logging,
    get_snapshot_date,
)

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Auto-detect latest snapshot
# ---------------------------------------------------------------------------

def detect_snapshot_date(base_dir: Path, requested: str) -> str:
    if not base_dir.exists():
        return requested
    available = sorted([
        p.name.replace("snapshot_date=", "")
        for p in base_dir.iterdir()
        if p.is_dir() and p.name.startswith("snapshot_date=")
    ], reverse=True)
    if not available:
        return requested
    if requested in available:
        return requested
    latest = available[0]
    _log.warning("No data for %s, using latest: %s", requested, latest)
    return latest


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load_scored(snapshot_date: str) -> tuple[pd.DataFrame, str]:
    actual_date = detect_snapshot_date(GOLD_VULN_SCORES_FINAL_DIR, snapshot_date)
    partition_path = GOLD_VULN_SCORES_FINAL_DIR / f"snapshot_date={actual_date}"

    if partition_path.exists():
        parquet_files = [
            f for f in partition_path.rglob("*.parquet")
            if not f.name.startswith(".")
        ]
    else:
        parquet_files = [
            f for f in GOLD_VULN_SCORES_FINAL_DIR.rglob("*.parquet")
            if not f.name.startswith(".")
        ]

    if not parquet_files:
        _log.error("No parquet files found")
        return pd.DataFrame(), actual_date

    _log.info("Found %d parquet files — loading all", len(parquet_files))
    dfs = [pd.read_parquet(f) for f in parquet_files]
    pdf = pd.concat(dfs, ignore_index=True)

    if "cve_id" in pdf.columns:
        pdf = pdf.drop_duplicates(subset="cve_id")

    pdf["priority_score_final"] = pd.to_numeric(
        pdf.get("priority_score_final", 0), errors="coerce"
    ).fillna(0.0)
    pdf["epss_score"] = pd.to_numeric(
        pdf.get("epss_score", 0), errors="coerce"
    ).fillna(0.0)
    pdf["is_kev"] = pd.to_numeric(
        pdf.get("is_kev", 0), errors="coerce"
    ).fillna(0).astype(int)
    pdf["cvss_score"] = pd.to_numeric(
        pdf.get("cvss_score", 0), errors="coerce"
    ).fillna(0.0)
    if "cluster_id" in pdf.columns:
        pdf["cluster_id"] = pd.to_numeric(
            pdf["cluster_id"], errors="coerce"
        ).fillna(-1).astype(int)

    _log.info("Loaded %d rows from snapshot_date=%s", len(pdf), actual_date)
    return pdf, actual_date


# ---------------------------------------------------------------------------
# Write helper
# ---------------------------------------------------------------------------

def write_parquet(
    pdf: pd.DataFrame,
    path: Path,
    partition_col: str | None = None,
    snapshot_date: str | None = None,
) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if snapshot_date and partition_col:
        pdf = pdf.copy()
        pdf[partition_col] = snapshot_date
        out = path / f"{partition_col}={snapshot_date}"
        out.mkdir(parents=True, exist_ok=True)
        pq.write_table(
            pa.Table.from_pandas(pdf, preserve_index=False),
            out / "part-00000.parquet",
        )
    else:
        pq.write_table(
            pa.Table.from_pandas(pdf, preserve_index=False),
            path / "part-00000.parquet",
        )


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

def strategy_top_priority(pdf: pd.DataFrame, capacity: int) -> pd.DataFrame:
    return pdf.nlargest(capacity, "priority_score_final")


def strategy_high_epss(pdf: pd.DataFrame, capacity: int) -> pd.DataFrame:
    return pdf.nlargest(capacity, "epss_score")


def strategy_cluster_based(pdf: pd.DataFrame, capacity: int) -> pd.DataFrame:
    if "cluster_id" not in pdf.columns:
        return strategy_top_priority(pdf, capacity)
    n_clusters = pdf["cluster_id"].nunique()
    per_cluster = max(1, capacity // max(n_clusters, 1))
    selected = (
        pdf.groupby("cluster_id", group_keys=False)
        .apply(lambda g: g.nlargest(per_cluster, "priority_score_final"))
    )
    return selected.nlargest(capacity, "priority_score_final")


def strategy_kev_first(pdf: pd.DataFrame, capacity: int) -> pd.DataFrame:
    kev = pdf[pdf["is_kev"] == 1].nlargest(capacity, "priority_score_final")
    if len(kev) >= capacity:
        return kev.head(capacity)
    non_kev = pdf[pdf["is_kev"] == 0].nlargest(
        capacity - len(kev), "priority_score_final"
    )
    return pd.concat([kev, non_kev])


def strategy_hybrid(pdf: pd.DataFrame, capacity: int) -> pd.DataFrame:
    kev_slots = max(1, capacity // 2)
    combined = pd.concat([
        strategy_kev_first(pdf, kev_slots),
        strategy_cluster_based(pdf, capacity - kev_slots),
    ]).drop_duplicates(subset="cve_id")
    return combined.head(capacity)


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def compute_metrics(
    pdf_full: pd.DataFrame, pdf_sel: pd.DataFrame, name: str
) -> dict:
    n_kev_total = int((pdf_full["is_kev"] == 1).sum())
    n_kev_sel = int((pdf_sel["is_kev"] == 1).sum())
    n_sel = len(pdf_sel)

    entropy = 0.0
    if n_sel > 0 and "cluster_id" in pdf_sel.columns:
        for cnt in pdf_sel["cluster_id"].value_counts():
            p = cnt / n_sel
            if p > 0:
                entropy -= p * math.log2(p)

    return {
        "strategy": name,
        "kev_coverage": round(n_kev_sel / n_kev_total, 4) if n_kev_total else 0.0,
        "epss_expected_mitigated": round(float(pdf_sel["epss_score"].sum()), 4),
        "cluster_diversity": round(entropy, 4),
        "mean_priority_selected": (
            round(float(pdf_sel["priority_score_final"].mean()), 4) if n_sel else 0.0
        ),
        "n_selected": n_sel,
    }


# ---------------------------------------------------------------------------
# Multi-day simulation
# ---------------------------------------------------------------------------

def simulate_multi_day(
    pdf: pd.DataFrame,
    daily_capacity: int,
    n_days: int,
    arrival_rate: int,
    snapshot_date: str,
) -> None:
    _log.info("Running multi-day simulation: %d days", n_days)
    strategy_fns = {
        "top_priority": strategy_top_priority,
        "high_epss": strategy_high_epss,
        "cluster_based": strategy_cluster_based,
        "kev_first": strategy_kev_first,
        "hybrid": strategy_hybrid,
    }
    rows = []
    for name, fn in strategy_fns.items():
        backlog = pdf.copy()
        cumulative_epss = 0.0
        for day in range(1, n_days + 1):
            if backlog.empty:
                rows.append({
                    "strategy": name, "day": day, "backlog_size": 0,
                    "kev_in_backlog": 0,
                    "cumulative_mitigated_epss": round(cumulative_epss, 4),
                    "mean_age_in_backlog": 0.0,
                })
                continue
            selected = fn(backlog, daily_capacity)
            cumulative_epss += float(selected["epss_score"].sum())
            backlog = backlog[~backlog["cve_id"].isin(selected["cve_id"])]
            if arrival_rate > 0 and not pdf.empty:
                arrivals = pdf.sample(
                    n=min(arrival_rate, len(pdf)), replace=True
                )
                backlog = pd.concat(
                    [backlog, arrivals]
                ).drop_duplicates(subset="cve_id")
            rows.append({
                "strategy": name,
                "day": day,
                "backlog_size": len(backlog),
                "kev_in_backlog": int((backlog["is_kev"] == 1).sum()),
                "cumulative_mitigated_epss": round(cumulative_epss, 4),
                "mean_age_in_backlog": float(day),
            })

    write_parquet(
        pd.DataFrame(rows),
        GOLD_SIMULATION_TIMESERIES_DIR,
        partition_col="snapshot_date",
        snapshot_date=snapshot_date,
    )
    _log.info("Simulation timeseries written.")


# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------

def run_capacity_simulation(
    snapshot_date: str,
    daily_capacity: int = DEFAULT_DAILY_CAPACITY,
    simulation_days: int = DEFAULT_SIMULATION_DAYS,
    arrival_rate: int = DEFAULT_ARRIVAL_RATE,
) -> None:
    pdf, actual_date = load_scored(snapshot_date)
    _log.info("Total CVEs: %d (snapshot_date=%s)", len(pdf), actual_date)

    if pdf.empty:
        _log.error("No data loaded — aborting.")
        return

    strategy_map = {
        "top_priority": strategy_top_priority,
        "high_epss": strategy_high_epss,
        "cluster_based": strategy_cluster_based,
        "kev_first": strategy_kev_first,
        "hybrid": strategy_hybrid,
    }

    # Strategy comparison + recommendations
    results = []
    for name, fn in strategy_map.items():
        selected = fn(pdf, daily_capacity)
        metrics = compute_metrics(pdf, selected, name)
        results.append(metrics)
        _log.info(
            "Strategy %s: kev_coverage=%.2f, epss_mitigated=%.2f",
            name, metrics["kev_coverage"], metrics["epss_expected_mitigated"],
        )
        rec_out = GOLD_REMEDIATION_RECOMMENDATIONS_DIR / name
        write_parquet(selected, rec_out)

    write_parquet(
        pd.DataFrame(results),
        GOLD_STRATEGY_COMPARISON_DIR,
        partition_col="snapshot_date",
        snapshot_date=actual_date,
    )
    _log.info("Strategy comparison written.")

    # Cluster risk summary
    if "cluster_id" not in pdf.columns:
        _log.warning("cluster_id missing — writing empty cluster summary")
        cluster_summary = pd.DataFrame(columns=[
            "cluster_id", "cluster_size", "avg_priority_final",
            "avg_cvss", "avg_epss", "max_epss", "kev_density", "n_kev",
        ])
    else:
        cluster_summary = (
            pdf.groupby("cluster_id")
            .agg(
                cluster_size=("cve_id", "count"),
                avg_priority_final=("priority_score_final", "mean"),
                avg_cvss=("cvss_score", "mean"),
                avg_epss=("epss_score", "mean"),
                max_epss=("epss_score", "max"),
                kev_density=("is_kev", "mean"),
                n_kev=("is_kev", "sum"),
            )
            .reset_index()
        )

    write_parquet(cluster_summary, GOLD_CLUSTER_RISK_SUMMARY_DIR)
    _log.info("Cluster risk summary written with %d clusters.", len(cluster_summary))

    # Multi-day simulation
    simulate_multi_day(pdf, daily_capacity, simulation_days, arrival_rate, actual_date)

    _log.info("Capacity simulation job complete.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--snapshot-date", default=get_snapshot_date(),
        help="Snapshot date (YYYY-MM-DD). Auto-detects latest if not found.",
    )
    parser.add_argument("--daily-capacity", type=int, default=DEFAULT_DAILY_CAPACITY)
    parser.add_argument("--simulation-days", type=int, default=DEFAULT_SIMULATION_DAYS)
    parser.add_argument("--arrival-rate", type=int, default=DEFAULT_ARRIVAL_RATE)
    return parser.parse_args()


def main() -> None:
    configure_logging()
    args = parse_args()
    run_capacity_simulation(
        snapshot_date=args.snapshot_date,
        daily_capacity=args.daily_capacity,
        simulation_days=args.simulation_days,
        arrival_rate=args.arrival_rate,
    )


if __name__ == "__main__":
    main()