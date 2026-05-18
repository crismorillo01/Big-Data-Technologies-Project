"""Vulnerability Intelligence Platform — Streamlit Dashboard.

Five pages accessed via the sidebar:
  1. Overview          — KPIs, data-quality cards, severity chart
  2. Vulnerability Explorer — searchable/filterable CVE table with detail view
  3. Cluster View      — cluster cards, bubble chart, top risky clusters
  4. Capacity Simulator — strategy comparison, multi-day simulation chart
  5. Remediation Plan  — ranked action table, CSV download

All data is read from the gold layer via src.utils.duckdb_helpers.
No direct pd.read_parquet() calls in this file.
"""

from __future__ import annotations

import datetime
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import pandas as pd
import plotly.express as px
import streamlit as st

from src.utils.duckdb_helpers import (
    available_snapshots,
    cluster_overview,
    data_quality_latest,
    overview_stats,
    remediation_actions,
    simulation_timeseries,
    strategy_comparison,
    top_n_vulnerabilities,
)

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="Vulnerability Intelligence Platform",
    page_icon="🛡️",
    layout="wide",
)

# ---------------------------------------------------------------------------
# Cached data loaders — all route through duckdb_helpers
# ---------------------------------------------------------------------------

@st.cache_data(ttl=300)
def _overview_stats(snapshot_date: str) -> pd.DataFrame:
    return overview_stats(snapshot_date)

@st.cache_data(ttl=300)
def _top_vulns(n, min_priority, only_kev, vendor, snapshot_date):
    return top_n_vulnerabilities(n, min_priority, only_kev, vendor or None, snapshot_date or None)

@st.cache_data(ttl=300)
def _cluster_overview():
    return cluster_overview()

@st.cache_data(ttl=300)
def _strategy_comparison():
    return strategy_comparison()

@st.cache_data(ttl=300)
def _remediation_actions(top_n, snapshot_date):
    return remediation_actions(top_n, snapshot_date or None)

@st.cache_data(ttl=300)
def _data_quality():
    return data_quality_latest()

@st.cache_data(ttl=300)
def _simulation_timeseries(snapshot_date):
    return simulation_timeseries(snapshot_date or None)

@st.cache_data(ttl=600)
def _available_snapshots():
    return available_snapshots()

# ---------------------------------------------------------------------------
# Sidebar navigation
# ---------------------------------------------------------------------------

st.sidebar.title("🛡️ VulnIntel Platform")
page = st.sidebar.radio(
    "Navigate",
    ["Overview", "Vulnerability Explorer", "Cluster View",
     "Capacity Simulator", "Remediation Plan"],
)

# Snapshot date selector
snapshots = _available_snapshots()
st.sidebar.markdown("### Snapshot date")
date_mode = st.sidebar.radio("Select mode", ["Latest", "Choose from list", "Pick any date"])

if date_mode == "Latest":
    snapshot_date = snapshots[0] if snapshots else None

elif date_mode == "Choose from list":
    snapshot_date = st.sidebar.selectbox(
        "Available snapshots",
        options=snapshots if snapshots else ["(none)"],
        format_func=lambda x: str(x)[:10],
    )
    snapshot_date = str(snapshot_date)[:10] if snapshot_date and snapshot_date != "(none)" else None

else:  # Pick any date
    picked = st.sidebar.date_input(
        "Pick a date",
        value=datetime.date.today(),
        min_value=datetime.date(2015, 1, 1),
        max_value=datetime.date.today(),
    )
    snapshot_date = str(picked)
    if snapshots and snapshot_date not in snapshots:
        st.sidebar.warning(f"No pipeline data for {snapshot_date}. Showing latest instead.")
        snapshot_date = snapshots[0] if snapshots else None

# Ensure clean YYYY-MM-DD string
if snapshot_date:
    snapshot_date = str(snapshot_date)[:10]

st.sidebar.markdown("---")
st.sidebar.caption("Data: NVD · CISA KEV · EPSS")


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _no_data(df: pd.DataFrame, message: str = "No data available.") -> bool:
    if df is None or df.empty:
        st.info(message)
        return True
    return False


# ---------------------------------------------------------------------------
# Page 1 — Overview
# ---------------------------------------------------------------------------

if page == "Overview":
    st.title("Overview")

    full_df = _overview_stats(snapshot_date or "")
    dq = _data_quality()

    # ---- KPI row -----------------------------------------------------------
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Total CVEs", f"{len(full_df):,}" if not full_df.empty else "—")
    with col2:
        n_kev = int(full_df["is_kev"].sum()) if not full_df.empty and "is_kev" in full_df.columns else 0
        st.metric("CISA KEV", f"{n_kev:,}")
    with col3:
        pct_crit = (
            100 * (full_df["priority_level_final"] == "Critical").mean()
            if not full_df.empty and "priority_level_final" in full_df.columns else 0
        )
        st.metric("% Critical", f"{pct_crit:.1f}%" if not full_df.empty else "—")
    with col4:
        mean_epss = full_df["epss_score"].mean() if not full_df.empty and "epss_score" in full_df.columns else 0
        st.metric("Mean EPSS", f"{mean_epss:.3f}" if not full_df.empty else "—")
    with col5:
        st.metric("Snapshot", snapshot_date or "—")

    st.markdown("---")

    # ---- Severity distribution chart ---------------------------------------
    st.subheader("Severity Distribution")
    if not full_df.empty and "cvss_severity" in full_df.columns:
        sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
        sev_counts = (
            full_df["cvss_severity"].str.upper()
            .value_counts()
            .reindex(sev_order, fill_value=0)
            .reset_index()
        )
        sev_counts.columns = ["Severity", "Count"]
        color_map = {
            "CRITICAL": "#d62728", "HIGH": "#ff7f0e",
            "MEDIUM": "#ffdd00", "LOW": "#2ca02c", "NONE": "#aec7e8",
        }
        fig = px.bar(
            sev_counts, x="Severity", y="Count",
            color="Severity", color_discrete_map=color_map,
            title="CVE Count by CVSS Severity",
        )
        fig.update_layout(showlegend=False)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Severity data not available.")

    # ---- Data quality ------------------------------------------------------
    st.markdown("---")
    st.subheader("Data Quality")
    if not _no_data(dq, "Data quality metrics not yet generated."):
        try:
            latest = dq.tail(1).copy()
            col_a, col_b = st.columns(2)
            with col_a:
                st.markdown("**Coverage**")
                coverage = {
                    "Total CVEs":       f"{int(latest['row_count'].iloc[0]):,}",
                    "Distinct CVEs":    f"{int(latest['distinct_cve_count'].iloc[0]):,}",
                    "KEV CVEs":         f"{int(latest['kev_count'].iloc[0]):,}",
                    "NVD ∩ KEV":        f"{int(latest['nvd_kev_intersection'].iloc[0]):,}",
                    "NVD ∩ EPSS":       f"{int(latest['nvd_epss_intersection'].iloc[0]):,}",
                    "NVD ∩ KEV ∩ EPSS": f"{int(latest['nvd_kev_epss_intersection'].iloc[0]):,}",
                }
                st.dataframe(
                    pd.DataFrame(coverage.items(), columns=["Metric", "Value"]),
                    hide_index=True, use_container_width=True,
                )
            with col_b:
                st.markdown("**Completeness & EPSS**")
                quality = {
                    "% Null CVSS":   f"{float(latest['pct_null_cvss'].iloc[0]):.2f}%",
                    "% Null EPSS":   f"{float(latest['pct_null_epss'].iloc[0]):.2f}%",
                    "% Null CWEs":   f"{float(latest['pct_null_cwes'].iloc[0]):.2f}%",
                    "% Null CPE":    f"{float(latest['pct_null_cpe'].iloc[0]):.2f}%",
                    "Mean EPSS":     f"{float(latest['mean_epss'].iloc[0]):.4f}",
                    "Median EPSS":   f"{float(latest['median_epss'].iloc[0]):.4f}",
                    "% EPSS > 0.7":  f"{float(latest['pct_epss_gt_07'].iloc[0]):.2f}%",
                    "% EPSS > 0.9":  f"{float(latest['pct_epss_gt_09'].iloc[0]):.2f}%",
                }
                st.dataframe(
                    pd.DataFrame(quality.items(), columns=["Metric", "Value"]),
                    hide_index=True, use_container_width=True,
                )
        except Exception as e:
            st.warning(f"Could not render data quality table: {e}")


# ---------------------------------------------------------------------------
# Page 2 — Vulnerability Explorer
# ---------------------------------------------------------------------------

elif page == "Vulnerability Explorer":
    st.title("Vulnerability Explorer")

    f1, f2, f3, f4 = st.columns(4)
    with f1:
        severity_filter = st.selectbox("Priority Level", ["All", "Critical", "High", "Medium", "Low"])
    with f2:
        vendor_filter = st.text_input("Vendor (contains)", "")
    with f3:
        min_epss = st.slider("Min EPSS", 0.0, 1.0, 0.0, 0.05)
    with f4:
        kev_only = st.checkbox("KEV only")

    min_priority = {"All": 0.0, "Critical": 0.8, "High": 0.6, "Medium": 0.4, "Low": 0.0}.get(
        severity_filter, 0.0
    )

    df = _top_vulns(500, min_priority, kev_only, vendor_filter or None, snapshot_date)

    if not df.empty and min_epss > 0 and "epss_score" in df.columns:
        df = df[df["epss_score"] >= min_epss]

    st.caption(f"{len(df):,} CVEs match your filters.")

    if not _no_data(df):
        display_cols = [c for c in [
            "cve_id", "priority_score_final", "priority_level_final",
            "cvss_score", "cvss_severity", "epss_score", "is_kev",
            "primary_vendor", "primary_product", "published",
        ] if c in df.columns]
        st.dataframe(df[display_cols].reset_index(drop=True), use_container_width=True)

        st.markdown("---")
        st.subheader("CVE Detail")
        cve_choice = st.selectbox(
            "Select CVE",
            options=df["cve_id"].tolist() if "cve_id" in df.columns else [],
        )
        if cve_choice:
            row = df[df["cve_id"] == cve_choice].iloc[0]
            d1, d2, d3 = st.columns(3)
            with d1:
                st.markdown(f"**CVE ID:** {row.get('cve_id', '—')}")
                st.markdown(f"**CVSS Score:** {row.get('cvss_score', '—')} ({row.get('cvss_severity', '—')})")
                st.markdown(f"**Priority Score:** {row.get('priority_score_final', '—')}")
                st.markdown(f"**Priority Level:** {row.get('priority_level_final', '—')}")
            with d2:
                st.markdown(f"**EPSS Score:** {row.get('epss_score', '—')}")
                st.markdown(f"**In KEV:** {'✅ Yes' if row.get('is_kev') == 1 else '❌ No'}")
                st.markdown(f"**Vendor:** {row.get('primary_vendor', '—')}")
                st.markdown(f"**Product:** {row.get('primary_product', '—')}")
            with d3:
                st.markdown(f"**Published:** {row.get('published', '—')}")
                st.markdown(f"**Last Modified:** {row.get('last_modified', '—')}")
                if row.get("kev_required_action"):
                    st.markdown(f"**Required Action:** {row['kev_required_action']}")
            if row.get("description"):
                st.markdown("**Description:**")
                st.write(row["description"])


# ---------------------------------------------------------------------------
# Page 3 — Cluster View
# ---------------------------------------------------------------------------

elif page == "Cluster View":
    st.title("Cluster View")

    clusters = _cluster_overview()

    if _no_data(clusters, "Cluster data not yet generated — run capacity_simulation first."):
        st.stop()

    st.caption(f"{len(clusters)} clusters found.")

    # Summary metrics
    c1, c2, c3 = st.columns(3)
    with c1:
        st.metric("Total Clusters", len(clusters))
    with c2:
        total_cves = int(clusters["cluster_size"].sum()) if "cluster_size" in clusters.columns else 0
        st.metric("Total CVEs Clustered", f"{total_cves:,}")
    with c3:
        high_kev = int((clusters["kev_density"] > 0.1).sum()) if "kev_density" in clusters.columns else 0
        st.metric("High KEV-density Clusters", high_kev)

    st.markdown("---")

    # Cluster risk table
    st.subheader("Cluster Risk Summary")
    display_cols = [c for c in [
        "cluster_id", "cluster_size", "kev_density", "n_kev",
        "avg_priority_final", "avg_cvss", "avg_epss", "max_epss",
    ] if c in clusters.columns]
    display_df = clusters[display_cols].copy()
    for col in ["kev_density", "avg_priority_final", "avg_cvss", "avg_epss", "max_epss"]:
        if col in display_df.columns:
            display_df[col] = display_df[col].round(4)
    st.dataframe(
        display_df.sort_values("kev_density", ascending=False).reset_index(drop=True),
        use_container_width=True, hide_index=True,
    )

    st.markdown("---")

    # Bubble chart
    st.subheader("Cluster Map: EPSS vs KEV Density")
    if all(c in clusters.columns for c in ["avg_epss", "kev_density", "cluster_size"]):
        fig = px.scatter(
            clusters,
            x="avg_epss", y="kev_density", size="cluster_size",
            color="avg_priority_final" if "avg_priority_final" in clusters.columns else None,
            hover_name="cluster_id",
            hover_data=["cluster_size", "n_kev", "avg_cvss"],
            labels={
                "avg_epss": "Mean EPSS Score",
                "kev_density": "KEV Density",
                "cluster_size": "Cluster Size",
            },
            title="Clusters: EPSS vs KEV Density (bubble size = cluster size)",
            color_continuous_scale="Reds",
        )
        fig.update_layout(height=500)
        st.plotly_chart(fig, use_container_width=True)

    # Top 5 riskiest clusters
    st.markdown("---")
    st.subheader("Top 5 Riskiest Clusters")
    if "kev_density" in clusters.columns:
        top5 = clusters.nlargest(5, "kev_density")
        for _, row in top5.iterrows():
            with st.expander(
                f"Cluster {int(row['cluster_id'])} — "
                f"{int(row['cluster_size'])} CVEs, "
                f"KEV density: {row['kev_density']:.2%}"
            ):
                m1, m2, m3, m4 = st.columns(4)
                with m1:
                    st.metric("Size", f"{int(row['cluster_size']):,}")
                with m2:
                    st.metric("KEV CVEs", f"{int(row['n_kev']):,}")
                with m3:
                    st.metric("Avg CVSS", f"{row['avg_cvss']:.2f}")
                with m4:
                    st.metric("Max EPSS", f"{row['max_epss']:.4f}")


# ---------------------------------------------------------------------------
# Page 4 — Capacity Simulator
# ---------------------------------------------------------------------------

elif page == "Capacity Simulator":
    st.title("Capacity Simulator")

    c1, c2, c3 = st.columns(3)
    with c1:
        daily_cap = st.slider("Daily Capacity (CVEs/day)", 10, 200, 50)
    with c2:
        sim_days = st.slider("Simulation Days", 7, 90, 30)
    with c3:
        strategy_pick = st.selectbox(
            "Highlight Strategy",
            ["top_priority", "high_epss", "cluster_based", "kev_first", "hybrid"],
        )

    # Strategy comparison table
    st.subheader("Strategy Comparison (one-day snapshot)")
    comp = _strategy_comparison()
    if not _no_data(comp):
        display_comp = [c for c in [
            "strategy", "kev_coverage", "epss_expected_mitigated",
            "cluster_diversity", "mean_priority_selected", "n_selected",
        ] if c in comp.columns]
        num_cols = [c for c in ["kev_coverage", "epss_expected_mitigated", "cluster_diversity"]
                    if c in comp.columns]
        styled = comp[display_comp].style.highlight_max(subset=num_cols, color="#d4edda")
        st.dataframe(styled, use_container_width=True)

    # Multi-day simulation
    st.subheader("Multi-day Simulation")
    ts = _simulation_timeseries(snapshot_date)
    if not _no_data(ts, "Simulation timeseries not yet generated."):
        metric_choice = st.selectbox(
            "Metric to plot",
            ["backlog_size", "kev_in_backlog", "cumulative_mitigated_epss"],
        )
        if metric_choice in ts.columns and "day" in ts.columns and "strategy" in ts.columns:
            fig = px.line(
                ts, x="day", y=metric_choice, color="strategy",
                title=f"{metric_choice.replace('_', ' ').title()} over time",
                labels={"day": "Day", metric_choice: metric_choice.replace("_", " ").title()},
            )
            for trace in fig.data:
                if trace.name == strategy_pick:
                    trace.line.width = 4
            st.plotly_chart(fig, use_container_width=True)


# ---------------------------------------------------------------------------
# Page 5 — Remediation Plan
# ---------------------------------------------------------------------------

elif page == "Remediation Plan":
    st.title("Remediation Plan")
    st.caption("Ranked patching actions by vendor + product. Higher action_score = more impact per unit effort.")

    top_n = st.slider("Show top N actions", 10, 200, 50)
    actions = _remediation_actions(top_n, snapshot_date)

    if _no_data(actions, "Remediation actions not yet generated."):
        st.stop()

    display_cols = [c for c in [
        "primary_vendor", "primary_product", "n_cves", "n_kev",
        "max_priority", "sum_priority", "mean_epss", "max_epss",
        "effort_proxy", "action_score",
    ] if c in actions.columns]
    st.dataframe(actions[display_cols].reset_index(drop=True), use_container_width=True)

    # Evidence CVEs
    st.markdown("---")
    st.subheader("Evidence CVEs")
    if "primary_vendor" in actions.columns and "primary_product" in actions.columns:
        choices = [
            f"{row['primary_vendor']} / {row['primary_product']}"
            for _, row in actions.head(top_n).iterrows()
        ]
        selected_action = st.selectbox("Select an action to see evidence CVEs", choices)
        if selected_action:
            vendor, product = selected_action.split(" / ", 1)
            row = actions[
                (actions["primary_vendor"] == vendor) &
                (actions["primary_product"] == product)
            ]
            if not row.empty and "top_cves" in row.columns:
                cves = row.iloc[0]["top_cves"]
                if cves is not None and len(cves) > 0:
                    st.markdown(f"**Top CVEs for {vendor}/{product}:**")
                    for cve in list(cves):
                        if cve:
                            st.markdown(f"- `{cve}`")

    # CSV download
    st.markdown("---")
    csv_data = actions[display_cols].to_csv(index=False).encode("utf-8")
    st.download_button(
        label="⬇️ Download as CSV",
        data=csv_data,
        file_name=f"remediation_plan_{snapshot_date or 'latest'}.csv",
        mime="text/csv",
    )