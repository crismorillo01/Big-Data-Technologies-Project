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

import sys
from html import escape
from pathlib import Path
from textwrap import dedent

# Ensure the project root is on sys.path so `src.*` imports work regardless
# of how Streamlit is launched (with or without PYTHONPATH=.).
# isort: off
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))
# isort: on

import pandas as pd
import plotly.express as px
import streamlit as st

from src.config import (
    DEFAULT_DAILY_CAPACITY,
    DEFAULT_SIMULATION_DAYS,
    PRIORITY_LEVEL_THRESHOLDS,
)
from src.utils.duckdb_helpers import (
    available_snapshots,
    cluster_overview,
    data_quality_latest,
    overview_stats,
    remediation_actions,
    remediation_recommendations,
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
# Custom CSS — sidebar card-nav + snapshot chips
# ---------------------------------------------------------------------------

st.markdown("""
<style>
/* ── Sidebar: reduce top padding ─────────────── */
[data-testid="stSidebar"] > div:first-child {
    padding-top: 1.2rem;
}

/* ── Nav buttons — base ──────────────────────── */
[data-testid="stSidebar"] .stButton button {
    text-align: left !important;
    justify-content: flex-start !important;
    border-radius: 8px !important;
    padding: 9px 14px !important;
    font-size: 14px !important;
    line-height: 1.4 !important;
    box-shadow: none !important;
    transition: background .12s, border-color .12s;
}
[data-testid="stSidebar"] .stButton {
    margin-bottom: 1px !important;
}

/* Inactive nav item */
[data-testid="stSidebar"] [data-testid="stBaseButton-secondary"] {
    background: transparent !important;
    border: 0.5px solid transparent !important;
    color: var(--text-color) !important;
    font-weight: 400 !important;
}
[data-testid="stSidebar"] [data-testid="stBaseButton-secondary"]:hover {
    background: var(--secondary-background-color) !important;
    border-color: rgba(49,51,63,0.12) !important;
}

/* Active nav item */
[data-testid="stSidebar"] [data-testid="stBaseButton-primary"] {
    background: var(--background-color) !important;
    border: 0.5px solid rgba(49,51,63,0.2) !important;
    color: var(--text-color) !important;
    font-weight: 600 !important;
}
[data-testid="stSidebar"] [data-testid="stBaseButton-primary"]:hover {
    background: var(--background-color) !important;
    border-color: rgba(49,51,63,0.3) !important;
}

/* ── Snapshot mode buttons (Latest / Custom) ─── */
[data-testid="stSidebar"] [data-testid="stHorizontalBlock"] [data-testid="stBaseButton-primary"],
[data-testid="stSidebar"] [data-testid="stHorizontalBlock"] [data-testid="stBaseButton-secondary"] {
    border-radius: 20px !important;
    padding: 5px 0 !important;
    font-size: 13px !important;
    text-align: center !important;
    justify-content: center !important;
    font-weight: 400 !important;
    box-shadow: none !important;
}
[data-testid="stSidebar"] [data-testid="stHorizontalBlock"] [data-testid="stBaseButton-primary"] {
    background: rgba(28,131,225,0.1) !important;
    border: 0.5px solid rgba(28,131,225,0.45) !important;
    color: rgb(28,131,225) !important;
    font-weight: 600 !important;
}
[data-testid="stSidebar"] [data-testid="stHorizontalBlock"] [data-testid="stBaseButton-secondary"] {
    background: transparent !important;
    border: 0.5px solid rgba(49,51,63,0.2) !important;
    color: var(--text-color) !important;
}

/* ── Snapshot selectbox: compact ─────────────── */
[data-testid="stSidebar"] [data-testid="stSelectbox"] {
    margin-top: 8px;
}

/* ── Global: all radios as chips ─────────────── */
/* (sidebar rules override these for the sidebar) */
[data-testid="stRadio"] > div {
    flex-direction: row !important;
    flex-wrap: wrap;
    gap: 6px !important;
}
[data-testid="stRadio"] > div > label {
    border: 0.5px solid rgba(49,51,63,0.2) !important;
    border-radius: 20px !important;
    padding: 5px 14px !important;
    font-size: 13px !important;
    cursor: pointer !important;
    margin: 0 !important;
    align-items: center !important;
    justify-content: center !important;
    transition: background .12s, border-color .12s;
}
/* Hide radio circle */
[data-testid="stRadio"] > div > label > div:first-child {
    display: none !important;
}
/* Center the text div that Streamlit sets to flex:1 */
[data-testid="stRadio"] > div > label > div:last-child {
    text-align: center !important;
    margin: 0 auto !important;
    flex: unset !important;
}
[data-testid="stRadio"] > div > label:has(input:checked) {
    background: rgba(28,131,225,0.1) !important;
    border-color: rgba(28,131,225,0.45) !important;
    color: rgb(28,131,225) !important;
    font-weight: 600 !important;
}

/* ── Global: filter buttons as small pills ────── */
/* sidebar-specific rules (higher specificity) override these */
[data-testid="stBaseButton-secondary"] {
    border-radius: 20px !important;
    padding: 5px 16px !important;
    font-size: 13px !important;
    box-shadow: none !important;
}
[data-testid="stBaseButton-primary"] {
    border-radius: 20px !important;
    padding: 5px 16px !important;
    font-size: 13px !important;
    box-shadow: none !important;
}

/* ── Priority level chip colors — only on selected ── */
/* Critical — 2nd option */
[data-testid="stRadio"] > div > label:nth-child(2):has(input:checked) {
    background: rgba(214,39,40,0.1) !important;
    border-color: rgba(214,39,40,0.65) !important;
    color: #c0282a !important;
}
/* High — 3rd option */
[data-testid="stRadio"] > div > label:nth-child(3):has(input:checked) {
    background: rgba(255,127,14,0.1) !important;
    border-color: rgba(255,127,14,0.65) !important;
    color: #c96e00 !important;
}
/* Medium — 4th option */
[data-testid="stRadio"] > div > label:nth-child(4):has(input:checked) {
    background: rgba(200,155,0,0.1) !important;
    border-color: rgba(200,155,0,0.65) !important;
    color: #a07d00 !important;
}
/* Low — 5th option */
[data-testid="stRadio"] > div > label:nth-child(5):has(input:checked) {
    background: rgba(44,160,44,0.1) !important;
    border-color: rgba(44,160,44,0.65) !important;
    color: #1d831d !important;
}
/* Reset sidebar radio chips — higher specificity cancels color bleed */
[data-testid="stSidebar"] [data-testid="stRadio"] > div > label:nth-child(n) {
    border-color: rgba(49,51,63,0.2) !important;
    color: inherit !important;
    background: transparent !important;
}
[data-testid="stSidebar"] [data-testid="stRadio"] > div > label:nth-child(n):has(input:checked) {
    background: rgba(28,131,225,0.1) !important;
    border-color: rgba(28,131,225,0.45) !important;
    color: rgb(28,131,225) !important;
}

/* ── KEV checkbox — plain normal checkbox ─────── */
[data-testid="stCheckbox"] > label {
    border: none !important;
    border-radius: 0 !important;
    padding: 4px 0 !important;
    background: transparent !important;
    display: inline-flex !important;
    align-items: center;
    gap: 8px !important;
    font-size: 13px;
    cursor: pointer;
}
/* Show the checkbox visual (was hidden before) */
[data-testid="stCheckbox"] > label > div:first-child {
    display: flex !important;
}
/* Restore native checkbox input appearance */
[data-testid="stCheckbox"] input[type="checkbox"] {
    appearance: auto !important;
    -webkit-appearance: auto !important;
    width: auto !important;
    height: auto !important;
    margin: 0 !important;
}
[data-testid="stCheckbox"] > label > div:last-child {
    margin: 0 !important;
}

/* ── Shared intel table ──────────────────────── */
.intel-table-shell {
    border: 1px solid rgba(128,128,128,0.24);
    border-radius: 10px;
    overflow-x: auto;
    margin: 0.5rem 0 1.25rem;
}
.intel-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.92rem;
}
.intel-table th {
    background: var(--secondary-background-color);
    color: rgba(128,128,128,0.9);
    font-weight: 600;
    padding: 0.75rem 0.7rem;
    text-align: left;
    white-space: nowrap;
    position: sticky;
    top: 0;
    z-index: 1;
}
.intel-table td {
    border-top: 1px solid rgba(128,128,128,0.2);
    padding: 0.72rem 0.7rem;
    vertical-align: middle;
}
.intel-table tr:hover td {
    background: rgba(28,131,225,0.08);
}
.intel-number {
    font-variant-numeric: tabular-nums;
    text-align: right;
}
.intel-kev-val {
    color: #ff5b61;
    font-weight: 600;
}
.intel-badge {
    border-radius: 999px;
    display: inline-flex;
    font-size: 0.82rem;
    font-weight: 700;
    justify-content: center;
    min-width: 5.1rem;
    padding: 0.24rem 0.68rem;
}
.intel-mono {
    font-family: monospace;
    font-size: 0.88rem;
}
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Cached data loaders — all route through duckdb_helpers
# ---------------------------------------------------------------------------


@st.cache_data(ttl=300)
def _overview_stats(snapshot_date: str) -> pd.DataFrame:
    return overview_stats(snapshot_date)


@st.cache_data(ttl=300)
def _top_vulns(n, priority_level, only_kev, vendor, snapshot_date):
    return top_n_vulnerabilities(n, priority_level, only_kev, vendor or None, snapshot_date or None)


@st.cache_data(ttl=300)
def _cluster_overview(snapshot_date):
    return cluster_overview(snapshot_date or None)


@st.cache_data(ttl=300)
def _strategy_comparison(snapshot_date):
    return strategy_comparison(snapshot_date or None)


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
# Sidebar
# ---------------------------------------------------------------------------


# Brand header
st.sidebar.markdown(
    """
    <div style="display:flex;align-items:center;gap:10px;
                padding-bottom:14px;margin-bottom:6px;
                border-bottom:0.5px solid rgba(49,51,63,0.12);">
      <span style="font-size:22px;line-height:1;">🛡️</span>
      <div>
        <p style="margin:0;font-size:15px;font-weight:600;line-height:1.3;">VulnIntel</p>
        <p style="margin:0;font-size:11px;color:gray;line-height:1.3;">Vulnerability Intelligence</p>
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)

_NAV_ITEMS = [
    ("📊", "Overview"),
    ("🔍", "Vulnerability Explorer"),
    ("🔗", "Cluster View"),
    ("📈", "Capacity Simulator"),
    ("✅", "Remediation Plan"),
]

# Navigation — session_state + buttons (styled as card items via CSS)
_query_page = st.query_params.get("page")
if isinstance(_query_page, list):
    _query_page = _query_page[-1] if _query_page else None
_nav_labels = {_label for _, _label in _NAV_ITEMS}
if "page" not in st.session_state:
    st.session_state.page = _query_page if _query_page in _nav_labels else "Overview"


def _nav_click(label: str) -> None:
    """on_click callback: updates page before Streamlit's natural rerun.

    Using on_click instead of st.rerun() inside the button block avoids a
    double-rerun that would reset sidebar widget states (e.g. snapshot radio).
    """
    st.session_state.page = label


for _icon, _label in _NAV_ITEMS:
    _is_active = st.session_state.page == _label
    st.sidebar.button(
        f"{_icon}  {_label}",
        key=f"nav_{_label}",
        use_container_width=True,
        type="primary" if _is_active else "secondary",
        on_click=_nav_click,
        args=(_label,),
    )

page = st.session_state.page

# Snapshot date selector
snapshots = _available_snapshots()

# Snapshot state — stored explicitly in session_state so navigation never resets it.
if "snapshot_mode" not in st.session_state:
    st.session_state.snapshot_mode = "Latest"
if "snapshot_custom_date" not in st.session_state:
    st.session_state.snapshot_custom_date = snapshots[0] if snapshots else None


def _snap_set_latest() -> None:
    st.session_state.snapshot_mode = "Latest"


def _snap_set_custom() -> None:
    st.session_state.snapshot_mode = "Custom"


st.sidebar.markdown("---")
st.sidebar.markdown(
    '<p style="font-size:11px;font-weight:600;letter-spacing:.05em;'
    'opacity:.5;text-transform:uppercase;margin:4px 0 6px 0;">Snapshot</p>',
    unsafe_allow_html=True,
)

_sc1, _sc2 = st.sidebar.columns(2)
with _sc1:
    st.button(
        "Latest",
        key="snap_btn_latest",
        use_container_width=True,
        type="primary" if st.session_state.snapshot_mode == "Latest" else "secondary",
        on_click=_snap_set_latest,
    )
with _sc2:
    st.button(
        "Custom",
        key="snap_btn_custom",
        use_container_width=True,
        type="primary" if st.session_state.snapshot_mode == "Custom" else "secondary",
        on_click=_snap_set_custom,
    )

if st.session_state.snapshot_mode == "Custom":
    _snap_opts = snapshots if snapshots else ["(none)"]
    # Restore previously chosen date if still in the list
    _snap_default = 0
    if st.session_state.snapshot_custom_date and _snap_opts[0] != "(none)":
        _snap_strs = [str(s)[:10] for s in _snap_opts]
        _prev = str(st.session_state.snapshot_custom_date)[:10]
        if _prev in _snap_strs:
            _snap_default = _snap_strs.index(_prev)
    _sel = st.sidebar.selectbox(
        "Available snapshots",
        options=_snap_opts,
        index=_snap_default,
        format_func=lambda x: str(x)[:10],
        label_visibility="collapsed",
    )
    snapshot_date = str(_sel)[:10] if _sel and _sel != "(none)" else None
    st.session_state.snapshot_custom_date = snapshot_date  # persist across page changes
else:
    snapshot_date = snapshots[0] if snapshots else None

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


def _first_int(df: pd.DataFrame, column: str) -> int | None:
    if df is None or df.empty or column not in df.columns:
        return None
    values = pd.to_numeric(df[column], errors="coerce").dropna()
    return int(values.iloc[0]) if not values.empty else None


def _simulation_settings(comp: pd.DataFrame, ts: pd.DataFrame) -> tuple[int, int]:
    daily_capacity = (
        _first_int(comp, "daily_capacity")
        or _first_int(ts, "daily_capacity")
        or DEFAULT_DAILY_CAPACITY
    )
    simulation_days = (
        _first_int(comp, "simulation_days")
        or _first_int(ts, "simulation_days")
    )

    if simulation_days is None and ts is not None and not ts.empty and "day" in ts.columns:
        days = pd.to_numeric(ts["day"], errors="coerce").dropna()
        simulation_days = int(days.max()) if not days.empty else None

    return daily_capacity, simulation_days or DEFAULT_SIMULATION_DAYS


def _priority_label(score) -> str:
    try:
        numeric_score = float(score)
    except (TypeError, ValueError):
        return "Unknown"

    for label in ("Critical", "High", "Medium"):
        if numeric_score >= PRIORITY_LEVEL_THRESHOLDS[label]:
            return label
    return "Low"


def _as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if hasattr(value, "tolist"):
        value = value.tolist()
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return []


# ---------------------------------------------------------------------------
# Page 1 — Overview
# ---------------------------------------------------------------------------

if page == "Overview":
    st.title("Overview")
    st.caption(f"Snapshot: {snapshot_date or 'latest'}")

    full_df = _overview_stats(snapshot_date or "")
    dq = _data_quality()

    # Pre-compute KPIs used in multiple places
    n_total = len(full_df) if not full_df.empty else 0
    n_kev = (
        int(full_df["is_kev"].sum())
        if not full_df.empty and "is_kev" in full_df.columns else 0
    )
    pct_crit = (
        100 * (full_df["priority_level_final"] == "Critical").mean()
        if not full_df.empty and "priority_level_final" in full_df.columns else 0.0
    )
    n_high_epss = (
        int((full_df["epss_score"] > 0.7).sum())
        if not full_df.empty and "epss_score" in full_df.columns else 0
    )

    # ---- KPI row (4 metrics) -----------------------------------------------
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total CVEs", f"{n_total:,}" if not full_df.empty else "—")
    with col2:
        st.metric("CISA KEV", f"{n_kev:,}")
    with col3:
        st.metric("% Critical",
                  f"{pct_crit:.1f}%" if not full_df.empty else "—")
    with col4:
        st.metric("EPSS > 0.7", f"{n_high_epss:,}")

    st.markdown("---")

    # ---- Severity chart (horizontal, full width) ----------------------------
    st.subheader("CVSS Severity")
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
            sev_counts, x="Count", y="Severity",
            color="Severity", color_discrete_map=color_map,
            orientation="h",
        )
        fig.update_layout(
            showlegend=False, height=260,
            margin=dict(t=10, b=20, l=0, r=20),
        )
        fig.update_yaxes(categoryorder="array", categoryarray=sev_order[::-1])
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Severity data not available.")

    # ---- Data Quality — progress bars --------------------------------------
    st.markdown("---")
    st.subheader("Data Quality")
    if not _no_data(dq, "Data quality metrics not yet generated."):
        try:
            latest = dq.tail(1).copy()

            def _bar_color(pct):
                if pct >= 85:
                    return "#639922"
                if pct >= 60:
                    return "#EF9F27"
                return "#d62728"

            def _progress_row(label, pct, color=None):
                c = color or _bar_color(pct)
                fill = min(max(pct, 0), 100)
                return (
                    f'<div style="display:flex;align-items:center;gap:10px;margin-bottom:9px;">'
                    f'<span style="width:80px;font-size:12px;color:gray;flex-shrink:0;">{label}</span>'
                    f'<div style="flex:1;height:8px;background:rgba(49,51,63,0.08);'
                    f'border-radius:4px;overflow:hidden;">'
                    f'<div style="width:{fill:.1f}%;height:100%;background:{c};'
                    f'border-radius:4px;"></div></div>'
                    f'<span style="width:42px;text-align:right;font-size:12px;'
                    f'font-weight:500;">{pct:.1f}%</span>'
                    f'</div>'
                )

            pct_null_cvss = float(latest["pct_null_cvss"].iloc[0])
            pct_null_epss = float(latest["pct_null_epss"].iloc[0])
            pct_null_cwes = float(latest["pct_null_cwes"].iloc[0])
            pct_null_cpe = float(latest["pct_null_cpe"].iloc[0])
            pct_epss_07 = float(latest["pct_epss_gt_07"].iloc[0])
            pct_epss_09 = float(latest["pct_epss_gt_09"].iloc[0])
            mean_epss = float(latest["mean_epss"].iloc[0])
            median_epss = float(latest["median_epss"].iloc[0])

            dq_left, dq_right = st.columns(2)

            with dq_left:
                st.markdown("**Field completeness**")
                st.markdown(
                    _progress_row("CVSS", 100 - pct_null_cvss)
                    + _progress_row("EPSS", 100 - pct_null_epss)
                    + _progress_row("CWEs", 100 - pct_null_cwes)
                    + _progress_row("CPE",  100 - pct_null_cpe),
                    unsafe_allow_html=True,
                )

            with dq_right:
                st.markdown("**EPSS Distribution**")
                st.markdown(
                    _progress_row("EPSS > 0.7", pct_epss_07, "#378ADD")
                    + _progress_row("EPSS > 0.9", pct_epss_09, "#378ADD")
                    + f'<p style="font-size:12px;color:gray;margin-top:10px;">'
                      f'Mean: <strong>{mean_epss:.4f}</strong> &nbsp;·&nbsp; '
                      f'Median: <strong>{median_epss:.4f}</strong></p>',
                    unsafe_allow_html=True,
                )

        except Exception as e:
            st.warning(f"Could not render data quality: {e}")


# ---------------------------------------------------------------------------
# Page 2 — Vulnerability Explorer
# ---------------------------------------------------------------------------

elif page == "Vulnerability Explorer":
    st.title("Vulnerability Explorer")

    # ---- Filter bar --------------------------------------------------------
    fcol1, fcol2, fcol3 = st.columns([4, 2, 1])
    with fcol1:
        severity_filter = st.radio(
            "Priority level",
            ["All", "Critical", "High", "Medium", "Low"],
            horizontal=True,
            key="explorer_sev",
        )
    with fcol2:
        vendor_filter = st.text_input(
            "Vendor", "", placeholder="e.g. microsoft")
    with fcol3:
        kev_only = st.checkbox("KEV only", key="kev_check")

    with st.expander("Advanced filters"):
        min_epss = st.slider("Min EPSS score", 0.0, 1.0, 0.0, 0.05)

    # ---- Load and filter data ----------------------------------------------
    df = _top_vulns(500, severity_filter, kev_only,
                    vendor_filter or None, snapshot_date)

    if not df.empty and min_epss > 0 and "epss_score" in df.columns:
        df = df[df["epss_score"] >= min_epss]

    # ---- Results count + CSV export ----------------------------------------
    res1, res2 = st.columns([7, 1])
    with res1:
        st.caption(f"{len(df):,} CVEs match your filters.")
    with res2:
        if not df.empty:
            _export_cols = [c for c in [
                "cve_id", "priority_score_final", "priority_level_final",
                "cvss_score", "cvss_severity", "epss_score", "is_kev",
                "primary_vendor", "primary_product", "published",
            ] if c in df.columns]
            st.download_button(
                "Export CSV",
                data=df[_export_cols].to_csv(index=False).encode("utf-8"),
                file_name=f"vulnerabilities_{snapshot_date or 'latest'}.csv",
                mime="text/csv",
                use_container_width=True,
            )

    # ---- Main table with visual severity indicators ------------------------
    if not _no_data(df):
        _VP_COLOR = {"Critical": "#c0282a", "High": "#c96e00",
                     "Medium": "#a07d00", "Low": "#1d831d"}
        _VP_BG = {
            "Critical": "rgba(214,39,40,0.16)",
            "High":    "rgba(255,127,14,0.16)",
            "Medium":  "rgba(200,155,0,0.16)",
            "Low":     "rgba(44,160,44,0.16)",
        }
        _vuln_rows = []
        for _, _vrow in df.iterrows():
            _vlevel = str(_vrow.get("priority_level_final") or "")
            _vpc = _VP_COLOR.get(_vlevel, "gray")
            _vpb = _VP_BG.get(_vlevel, "rgba(128,128,128,0.12)")
            _vcve = escape(str(_vrow.get("cve_id") or "—"))
            _vscore = _vrow.get("priority_score_final")
            _vscore_s = f"{float(_vscore):.1f}" if _vscore is not None and pd.notna(
                _vscore) else "—"
            _vcvss = _vrow.get("cvss_score")
            _vcvss_s = f"{float(_vcvss):.1f}" if _vcvss is not None and pd.notna(
                _vcvss) else "—"
            _vepss = _vrow.get("epss_score")
            _vepss_s = f"{float(_vepss):.3f}" if _vepss is not None and pd.notna(
                _vepss) else "—"
            _vkev = (
                '<span class="explorer-kev-badge">KEV</span>'
                if _vrow.get("is_kev") == 1
                else '<span class="explorer-kev-muted">—</span>'
            )
            _vvendor = escape(str(_vrow.get("primary_vendor") or "—"))
            _vproduct = escape(str(_vrow.get("primary_product") or "—"))
            _vpub = str(_vrow.get("published") or "—")[:10]
            _vbadge = (
                f'<span class="explorer-badge" style="color:{_vpc};background:{_vpb};">'
                f'{escape(_vlevel)}</span>'
            ) if _vlevel else "—"
            _vuln_rows.append(
                f'<tr>'
                f'<td class="explorer-mono">{_vcve}</td>'
                f'<td class="explorer-number">{_vscore_s}</td>'
                f'<td>{_vbadge}</td>'
                f'<td class="explorer-number">{_vcvss_s}</td>'
                f'<td class="explorer-number">{_vepss_s}</td>'
                f'<td style="text-align:center;">{_vkev}</td>'
                f'<td>{_vvendor}</td>'
                f'<td>{_vproduct}</td>'
                f'<td>{_vpub}</td>'
                f'</tr>'
            )
        st.markdown(
            '<style>'
            '.explorer-table-shell {'
            '  border: 1px solid rgba(128,128,128,0.24);'
            '  border-radius: 14px;'
            '  max-height: 420px;'
            '  overflow: auto;'
            '  margin-top: 0.75rem;'
            '}'
            '.explorer-table {'
            '  width: 100%;'
            '  min-width: 760px;'
            '  border-collapse: collapse;'
            '  font-size: 0.92rem;'
            '}'
            '.explorer-table thead th {'
            '  background: rgba(128,128,128,0.12);'
            '  color: rgba(250,250,250,0.72);'
            '  padding: 0.82rem 0.7rem;'
            '  text-align: left;'
            '  white-space: nowrap;'
            '  font-weight: 600;'
            '}'
            '.explorer-table tbody td {'
            '  border-top: 1px solid rgba(128,128,128,0.16);'
            '  padding: 0.72rem 0.7rem;'
            '  vertical-align: middle;'
            '}'
            '.explorer-table tbody tr:hover {'
            '  background: rgba(28,131,225,0.08);'
            '}'
            '.explorer-number {'
            '  text-align: right;'
            '  font-variant-numeric: tabular-nums;'
            '}'
            '.explorer-mono {'
            '  font-family: monospace;'
            '  font-variant-numeric: tabular-nums;'
            '}'
            '.explorer-badge {'
            '  border-radius: 999px;'
            '  display: inline-flex;'
            '  font-size: 0.82rem;'
            '  font-weight: 700;'
            '  justify-content: center;'
            '  min-width: 5.1rem;'
            '  padding: 0.24rem 0.68rem;'
            '}'
            '.explorer-kev-badge {'
            '  align-items: center;'
            '  background: rgba(255,91,97,0.14);'
            '  border-radius: 999px;'
            '  color: #ff5b61;'
            '  display: inline-flex;'
            '  font-size: 0.82rem;'
            '  font-weight: 700;'
            '  justify-content: center;'
            '  min-width: 2.2rem;'
            '  padding: 0.24rem 0.68rem;'
            '}'
            '.explorer-kev-muted {'
            '  color: rgba(250,250,250,0.58);'
            '}'
            '</style>',
            unsafe_allow_html=True,
        )
        st.markdown(
            '<div class="explorer-table-shell"><table class="explorer-table">'
            '<thead><tr>'
            '<th>CVE ID</th><th>Score</th><th>Level</th><th>CVSS</th>'
            '<th>EPSS</th><th>KEV</th><th>Vendor</th><th>Product</th><th>Published</th>'
            '</tr></thead><tbody>'
            + "".join(_vuln_rows)
            + '</tbody></table></div>',
            unsafe_allow_html=True,
        )

        # ---- CVE Detail card -----------------------------------------------
        st.markdown("---")
        cve_choice = st.selectbox(
            "CVE detail",
            options=df["cve_id"].tolist() if "cve_id" in df.columns else [],
            label_visibility="collapsed",
            placeholder="Search a CVE ID for details…",
        )
        if cve_choice:
            row = df[df["cve_id"] == cve_choice].iloc[0]

            is_kev = row.get("is_kev") == 1
            level = str(row.get("priority_level_final") or "")
            epss_val = row.get("epss_score")
            epss_str = f"{float(epss_val):.3f}" if epss_val is not None and pd.notna(
                epss_val) else "—"
            cvss_val = row.get("cvss_score")
            cvss_str = f"{float(cvss_val):.1f}" if cvss_val is not None and pd.notna(
                cvss_val) else "—"
            score_val = row.get("priority_score_final")
            score_str = f"{float(score_val):.1f}" if score_val is not None and pd.notna(
                score_val) else "—"

            _LEVEL_STYLE = {
                "Critical": ("background:#FCEBEB;color:#A32D2D;", "#A32D2D"),
                "High":     ("background:#FAEEDA;color:#854F0B;", "#854F0B"),
                "Medium":   ("background:#FFF8E1;color:#6D4C0B;", "#6D4C0B"),
                "Low":      ("background:#EAF3DE;color:#3B6D11;", "#3B6D11"),
            }
            badge_style, score_color = _LEVEL_STYLE.get(
                level, ("background:#F1EFE8;color:#5F5E5A;", "#5F5E5A"))

            level_badge = (
                f'<span style="{badge_style}padding:3px 10px;border-radius:12px;'
                f'font-size:12px;font-weight:500;">{level}</span>'
            ) if level else ""

            kev_badge = (
                '<span style="background:#FCEBEB;border:0.5px solid #F09595;color:#A32D2D;'
                'padding:3px 10px;border-radius:12px;font-size:12px;font-weight:500;">⚠️ CISA KEV</span>'
            ) if is_kev else ""

            desc_html = (
                '<div style="padding-top:12px;margin-top:12px;'
                'border-top:0.5px solid rgba(49,51,63,0.08);'
                'font-size:13px;line-height:1.7;">'
                + str(row["description"])
                + "</div>"
            ) if row.get("description") else ""

            action_html = (
                '<div style="margin-top:10px;padding:10px 14px;background:#FCEBEB;'
                'border-radius:8px;font-size:13px;color:#A32D2D;">'
                '<strong>Required action:</strong> '
                + str(row["kev_required_action"])
                + "</div>"
            ) if row.get("kev_required_action") else ""

            st.markdown(
                f"""
                <div style="border:0.5px solid rgba(49,51,63,0.2);border-radius:12px;
                            padding:1.2rem 1.4rem;margin-top:4px;">
                  <div style="display:flex;align-items:center;gap:10px;padding-bottom:14px;
                              margin-bottom:14px;border-bottom:0.5px solid rgba(49,51,63,0.08);">
                    <span style="font-size:17px;font-weight:600;font-family:monospace;">
                      {row.get("cve_id", "—")}
                    </span>
                    {level_badge}
                    {kev_badge}
                  </div>
                  <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:14px;">
                    <div>
                      <p style="margin:0 0 3px;font-size:11px;color:gray;">Priority score</p>
                      <p style="margin:0;font-size:22px;font-weight:500;color:{score_color};">{score_str}</p>
                    </div>
                    <div>
                      <p style="margin:0 0 3px;font-size:11px;color:gray;">CVSS score</p>
                      <p style="margin:0;font-size:22px;font-weight:500;">{cvss_str}</p>
                      <p style="margin:0;font-size:11px;color:gray;">{row.get("cvss_severity", "")}</p>
                    </div>
                    <div>
                      <p style="margin:0 0 3px;font-size:11px;color:gray;">EPSS score</p>
                      <p style="margin:0;font-size:22px;font-weight:500;color:#185FA5;">{epss_str}</p>
                    </div>
                    <div>
                      <p style="margin:0 0 3px;font-size:11px;color:gray;">Vendor</p>
                      <p style="margin:0;font-size:13px;font-weight:500;">{row.get("primary_vendor") or "—"}</p>
                    </div>
                    <div>
                      <p style="margin:0 0 3px;font-size:11px;color:gray;">Product</p>
                      <p style="margin:0;font-size:13px;font-weight:500;">{row.get("primary_product") or "—"}</p>
                    </div>
                    <div>
                      <p style="margin:0 0 3px;font-size:11px;color:gray;">Published</p>
                      <p style="margin:0;font-size:13px;font-weight:500;">{str(row.get("published") or "—")[:10]}</p>
                    </div>
                  </div>
                  {desc_html}
                  {action_html}
                </div>
                """,
                unsafe_allow_html=True,
            )


# ---------------------------------------------------------------------------
# Page 3 — Cluster View
# ---------------------------------------------------------------------------

elif page == "Cluster View":
    st.title("Cluster View")

    clusters = _cluster_overview(snapshot_date)

    if _no_data(clusters, "Cluster data not yet generated — run capacity_simulation first."):
        st.stop()

    # Summary metrics
    c1, c2, c3 = st.columns(3)
    with c1:
        st.metric("Total Clusters", len(clusters))
    with c2:
        total_cves = int(clusters["cluster_size"].sum(
        )) if "cluster_size" in clusters.columns else 0
        st.metric("Total CVEs Clustered", f"{total_cves:,}")
    with c3:
        high_kev = int((clusters["n_kev"] > 0).sum(
        )) if "n_kev" in clusters.columns else 0
        st.metric("Clusters with KEV CVEs", high_kev)

    st.markdown("---")

    # Cluster risk table
    st.subheader("Cluster Risk Summary")
    _cl_cols = [c for c in [
        "cluster_id", "cluster_size", "kev_density", "n_kev",
        "avg_priority_final", "avg_cvss", "avg_epss", "max_epss",
    ] if c in clusters.columns]
    _cl_sorted = clusters[_cl_cols].sort_values(
        "kev_density", ascending=False
    ).reset_index(drop=True)
    _cl_rows = []
    for _, _crow in _cl_sorted.iterrows():
        def _cf(col, fmt=".4f", _r=_crow):
            v = _r.get(col)
            return format(float(v), fmt) if v is not None and pd.notna(v) else "—"

        def _ci(col, _r=_crow):
            v = _r.get(col)
            return f"{int(v):,}" if v is not None and pd.notna(v) else "—"
        _cl_rows.append(
            f'<tr>'
            f'<td class="cluster-number">{_ci("cluster_id")}</td>'
            f'<td class="cluster-number">{_ci("cluster_size")}</td>'
            f'<td class="cluster-number">{_cf("kev_density")}</td>'
            f'<td class="cluster-number cluster-kev">{_ci("n_kev")}</td>'
            f'<td class="cluster-number">{_cf("avg_priority_final")}</td>'
            f'<td class="cluster-number">{_cf("avg_cvss")}</td>'
            f'<td class="cluster-number">{_cf("avg_epss")}</td>'
            f'<td class="cluster-number">{_cf("max_epss")}</td>'
            f'</tr>'
        )
    st.markdown(
        '<style>'
        '.cluster-table-shell {'
        '  border: 1px solid rgba(128,128,128,0.24);'
        '  border-radius: 14px;'
        '  max-height: 420px;'
        '  overflow: auto;'
        '  margin: 0.5rem 0 1.25rem;'
        '}'
        '.cluster-table {'
        '  width: 100%;'
        '  min-width: 760px;'
        '  border-collapse: collapse;'
        '  font-size: 0.92rem;'
        '}'
        '.cluster-table thead th {'
        '  background: rgba(128,128,128,0.12);'
        '  color: rgba(250,250,250,0.72);'
        '  font-weight: 600;'
        '  padding: 0.82rem 0.7rem;'
        '  text-align: left;'
        '  white-space: nowrap;'
        '}'
        '.cluster-table tbody td {'
        '  border-top: 1px solid rgba(128,128,128,0.16);'
        '  padding: 0.72rem 0.7rem;'
        '  vertical-align: middle;'
        '}'
        '.cluster-table tbody tr:hover {'
        '  background: rgba(28,131,225,0.08);'
        '}'
        '.cluster-number {'
        '  text-align: right;'
        '  font-variant-numeric: tabular-nums;'
        '}'
        '.cluster-kev {'
        '  color: #ff5b61;'
        '  font-weight: 600;'
        '}'
        '</style>',
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="cluster-table-shell"><table class="cluster-table">'
        '<thead><tr>'
        '<th>Cluster</th><th>Size</th><th>KEV Density</th><th>KEV CVEs</th>'
        '<th>Avg Priority</th><th>Avg CVSS</th><th>Avg EPSS</th><th>Max EPSS</th>'
        '</tr></thead><tbody>'
        + "".join(_cl_rows)
        + '</tbody></table></div>',
        unsafe_allow_html=True,
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

    comp = _strategy_comparison(snapshot_date)
    ts = _simulation_timeseries(snapshot_date)
    daily_cap, sim_days = _simulation_settings(comp, ts)

    # ── Meta info row (read-only context) ───────────────────────────────────
    st.markdown(
        f'<div style="display:flex;gap:24px;margin-bottom:1.5rem;flex-wrap:wrap;">'
        f'<span style="font-size:12px;opacity:.6">Snapshot&nbsp;'
        f'<strong style="opacity:1">{snapshot_date or "Latest"}</strong></span>'
        f'<span style="font-size:12px;opacity:.6">Daily capacity&nbsp;'
        f'<strong style="opacity:1">{daily_cap:,} CVEs/day</strong></span>'
        f'<span style="font-size:12px;opacity:.6">Horizon&nbsp;'
        f'<strong style="opacity:1">{sim_days} days</strong></span>'
        f'</div>',
        unsafe_allow_html=True,
    )

    st.subheader("Strategy Comparison")
    # ── Strategy cards ───────────────────────────────────────────────────────
    _STRAT_COLORS = {
        "hybrid":       "#185FA5",
        "kev_first":    "#639922",
        "top_priority": "#BA7517",
        "high_epss":    "#A32D2D",
        "cluster_based": "#534AB7",
    }

    if not _no_data(comp):
        def _bar(pct: float, color: str) -> str:
            pct = max(0.0, min(100.0, pct))
            return (
                f'<div style="width:100%;height:3px;background:rgba(128,128,128,0.15);'
                f'border-radius:2px;margin-bottom:6px">'
                f'<div style="width:{pct:.0f}%;height:3px;background:{color};'
                f'opacity:.55;border-radius:2px"></div></div>'
            )

        _cards_html = (
            '<div style="display:grid;grid-template-columns:repeat(5,1fr);'
            'gap:8px;margin-bottom:1.5rem">'
        )
        for _, _row in comp.iterrows():
            _strat = _row.get("strategy", "")
            _color = _STRAT_COLORS.get(_strat, "#888")
            _kev = float(_row.get("kev_coverage", 0) or 0)
            _epss = float(_row.get("epss_expected_mitigated", 0) or 0)
            _div = float(_row.get("cluster_diversity", 0) or 0)
            _kev_p = _kev * 100 if _kev <= 1 else _kev
            _div_p = _div * 100 if _div <= 1 else _div
            _n_sel = int(_row.get("n_selected", 0) or 0)
            _label = _strat.replace("_", " ").title()
            _cards_html += (
                f'<div style="border:0.5px solid rgba(128,128,128,0.2);border-radius:12px;'
                f'padding:14px 12px;background:var(--background-color)">'
                f'<div style="font-size:14px;font-weight:600;margin-bottom:12px">{_label}</div>'
                f'<div style="font-size:12px;color:gray;margin-bottom:3px;display:flex;justify-content:space-between">'
                f'KEV coverage <span style="font-weight:600">{_kev_p:.0f}%</span></div>'
                f'{_bar(_kev_p, _color)}'
                f'<div style="font-size:12px;color:gray;margin-bottom:3px;display:flex;justify-content:space-between">'
                f'Exploit risk mitigated <span style="font-weight:600">{_epss:.2f}</span></div>'
                f'{_bar(_epss, _color)}'
                f'<div style="font-size:12px;color:gray;margin-bottom:3px;display:flex;justify-content:space-between">'
                f'Cluster diversity <span style="font-weight:600">{_div_p:.0f}%</span></div>'
                f'{_bar(_div_p, _color)}'
                f'<div style="font-size:12px;color:gray;margin-top:8px;padding-top:8px;'
                f'border-top:0.5px solid rgba(128,128,128,0.15);display:flex;justify-content:space-between">'
                f'Selected <span style="font-weight:600">{_n_sel:,}</span></div>'
                f'</div>'
            )
        _cards_html += '</div>'
        st.markdown(_cards_html, unsafe_allow_html=True)

    st.subheader("Simulation Over Time")
    # ── Multi-day simulation chart ───────────────────────────────────────────
    if not _no_data(ts, "Simulation timeseries not yet generated."):
        _METRIC_LABELS = {
            "backlog_size":             "Backlog size",
            "kev_in_backlog":           "KEV remaining",
            "cumulative_mitigated_epss": "Cumulative fixed",
        }
        _available_metrics = [m for m in _METRIC_LABELS if m in ts.columns]

        metric_choice = st.radio(
            "Metric",
            _available_metrics,
            format_func=lambda m: _METRIC_LABELS[m],
            horizontal=True,
            key="sim_metric",
        )

        if "day" in ts.columns and "strategy" in ts.columns and metric_choice in ts.columns:
            _fig = px.line(
                ts, x="day", y=metric_choice, color="strategy",
                color_discrete_map=_STRAT_COLORS,
                labels={
                    "day": "Day",
                    metric_choice: _METRIC_LABELS.get(metric_choice, metric_choice),
                    "strategy": "Strategy",
                },
            )
            _fig.update_traces(line_width=2, opacity=0.85)
            _fig.update_layout(
                plot_bgcolor="rgba(0,0,0,0)",
                paper_bgcolor="rgba(0,0,0,0)",
                margin=dict(t=10, b=10, l=0, r=10),
                legend=dict(
                    orientation="h", yanchor="top", y=-0.15,
                    xanchor="left", x=0, font=dict(size=11),
                ),
                xaxis=dict(showgrid=False, title="Day"),
                yaxis=dict(gridcolor="rgba(128,128,128,0.1)"),
            )
            st.plotly_chart(_fig, use_container_width=True)


# ---------------------------------------------------------------------------
# Page 5 — Remediation Plan
# ---------------------------------------------------------------------------

elif page == "Remediation Plan":
    st.title("Remediation Plan")
    st.caption(
        "Two views of the same remediation problem: one grouped by vendor/product, "
        "and one driven by capacity strategy selections."
    )

    vendor_tab, strategy_tab = st.tabs(["By vendor/product", "By capacity strategy"])

    with vendor_tab:
        st.caption(
            "Ranked patching actions by vendor · product. "
            "Higher action score = more impact per unit effort."
        )

        _rcol1, _rcol2 = st.columns([6, 2])
        with _rcol1:
            top_n = st.radio(
                "Show top",
                [10, 25, 50, 100],
                horizontal=True,
                key="rem_top_n",
            )
        actions = _remediation_actions(top_n, snapshot_date)

        if _no_data(actions, "Remediation actions not yet generated."):
            st.stop()

        actions = actions.reset_index(drop=True)

        _display_cols = [c for c in [
            "primary_vendor", "primary_product", "n_cves", "n_kev",
            "max_priority", "mean_epss", "action_score",
        ] if c in actions.columns]
        _export_cols = [c for c in [
            *_display_cols,
            "max_epss", "sum_priority", "effort_proxy", "top_cves",
        ] if c in actions.columns]

        with _rcol2:
            st.download_button(
                "Export CSV",
                data=actions[_export_cols].to_csv(index=False).encode("utf-8"),
                file_name=f"remediation_plan_{snapshot_date or 'latest'}.csv",
                mime="text/csv",
                use_container_width=True,
            )

        _P_COLOR = {"Critical": "#c0282a", "High": "#c96e00",
                    "Medium": "#a07d00", "Low": "#1d831d"}
        _P_BG = {
            "Critical": "rgba(214,39,40,0.16)",
            "High":    "rgba(255,127,14,0.16)",
            "Medium":  "rgba(200,155,0,0.16)",
            "Low":     "rgba(44,160,44,0.16)",
        }

        def _remediation_detail_card(row: pd.Series, idx: int) -> str:
            vendor = str(row.get("primary_vendor", "") or "")
            product = str(row.get("primary_product", "") or "")
            n_cves = int(row.get("n_cves", 0) or 0)
            n_kev = int(row.get("n_kev", 0) or 0)
            max_epss = float(row.get("max_epss", 0) or 0)
            action_score = float(row.get("action_score", 0) or 0)
            priority = _priority_label(row.get("max_priority"))
            top_cves = _as_list(row.get("top_cves"))
            initials = (vendor[:2] if vendor else "??").upper()
            pc = _P_COLOR.get(priority, "gray")
            pb = _P_BG.get(priority, "rgba(128,128,128,0.1)")
            cve_tags = " ".join(
                f'<span class="remediation-cve-tag">{escape(str(cve))}</span>'
                for cve in top_cves[:10] if cve
            ) or '<span class="remediation-muted">No CVE data available</span>'

            return f"""
<section class="remediation-detail-card remediation-detail-{idx}">
  <div class="remediation-detail-head">
    <div class="remediation-initials">{escape(initials)}</div>
    <div>
      <div class="remediation-detail-title">{escape(vendor)} / {escape(product)}</div>
      <div class="remediation-muted">{n_cves:,} CVEs &nbsp;·&nbsp; {n_kev:,} in KEV &nbsp;·&nbsp;
        <span class="remediation-detail-priority" style="background:{pb};color:{pc};">{priority}</span>
      </div>
    </div>
  </div>
  <div class="remediation-detail-metrics">
    <div><small>Total CVEs</small><strong>{n_cves:,}</strong></div>
    <div><small>KEV count</small><strong class="remediation-detail-kev">{n_kev:,}</strong></div>
    <div><small>Max EPSS</small><strong>{max_epss:.2f}</strong></div>
    <div><small>Action score</small><strong>{action_score:.2f}</strong></div>
  </div>
  <div class="remediation-muted remediation-top-cves">Top CVEs</div>
  <div class="remediation-cve-tags">{cve_tags}</div>
</section>
"""

        _max_action_score = float(actions["action_score"].max() or 1.0)
        _action_targets = []
        _table_rows = []
        _selection_css = []
        _detail_cards = []
        for _idx, _row in actions.iterrows():
            _control_id = f"remediation-action-{_idx}"
            _vendor = escape(str(_row.get("primary_vendor", "") or ""))
            _product = escape(str(_row.get("primary_product", "") or ""))
            _n_cves = int(_row.get("n_cves", 0) or 0)
            _n_kev = int(_row.get("n_kev", 0) or 0)
            _mean_epss = float(_row.get("mean_epss", 0) or 0)
            _score = float(_row.get("action_score", 0) or 0)
            _priority = _priority_label(_row.get("max_priority"))
            _pc = _P_COLOR.get(_priority, "gray")
            _pb = _P_BG.get(_priority, "rgba(128,128,128,0.12)")
            _score_width = max(0.0, min(100.0, 100 * _score / _max_action_score))
            _cells = (
                f'<td><a href="#{_control_id}">{_idx + 1}</a></td>'
                f'<td><a href="#{_control_id}">{_vendor}</a></td>'
                f'<td><a href="#{_control_id}">{_product}</a></td>'
                f'<td class="remediation-number"><a href="#{_control_id}">{_n_cves:,}</a></td>'
                f'<td class="remediation-number remediation-kev"><a href="#{_control_id}">{_n_kev:,}</a></td>'
                f'<td><a href="#{_control_id}"><span class="remediation-badge" '
                f'style="color:{_pc};background:{_pb};">{_priority}</span></a></td>'
                f'<td class="remediation-number"><a href="#{_control_id}">{_mean_epss:.2f}</a></td>'
                f'<td><a href="#{_control_id}"><span class="remediation-score">'
                f'<span class="remediation-score-track"><span style="width:{_score_width:.1f}%"></span></span>'
                f'<span>{_score:.2f}</span></span></a></td>'
            )
            _action_targets.append(
                f'<span class="remediation-target" id="{_control_id}"></span>')
            _table_rows.append(
                f'<tr class="remediation-row remediation-row-{_idx}">{_cells}</tr>')
            _selection_css.append(
                f'#{_control_id}:target ~ .remediation-table-shell .remediation-row-{_idx}'
                ' { background: rgba(28,131,225,0.18); }'
            )
            _selection_css.append(
                f'#{_control_id}:target ~ .remediation-details .remediation-detail-{_idx}'
                ' { display: block; }'
            )
            _detail_cards.append(_remediation_detail_card(_row, _idx))

        st.markdown(
            """
            <style>
            .remediation-target {
                display: block;
                height: 0;
                scroll-margin-top: 1rem;
            }
            .remediation-table-shell {
                border: 1px solid rgba(128,128,128,0.24);
                border-radius: 10px;
                max-height: 420px;
                overflow: auto;
                margin: 0.5rem 0 1.25rem;
            }
            .remediation-table {
                width: 100%;
                min-width: 760px;
                border-collapse: collapse;
                font-size: 0.92rem;
            }
            .remediation-table th {
                background: rgba(128,128,128,0.12);
                color: rgba(250,250,250,0.72);
                font-weight: 600;
                padding: 0.75rem 0.7rem;
                text-align: left;
                white-space: nowrap;
            }
            .remediation-table td {
                border-top: 1px solid rgba(128,128,128,0.2);
                padding: 0;
                vertical-align: middle;
            }
            .remediation-table td a {
                color: inherit;
                cursor: pointer;
                display: block;
                min-height: 2.85rem;
                padding: 0.72rem 0.7rem;
                text-decoration: none;
            }
            .remediation-row:hover {
                background: rgba(28,131,225,0.08);
            }
            .remediation-number {
                font-variant-numeric: tabular-nums;
                text-align: right;
            }
            .remediation-kev {
                color: #ff5b61;
                font-weight: 600;
            }
            .remediation-badge {
                border-radius: 999px;
                display: inline-flex;
                font-size: 0.82rem;
                font-weight: 700;
                justify-content: center;
                min-width: 5.1rem;
                padding: 0.24rem 0.68rem;
            }
            .remediation-score {
                align-items: center;
                display: grid;
                gap: 0.6rem;
                grid-template-columns: minmax(5.5rem, 1fr) auto;
                font-variant-numeric: tabular-nums;
            }
            .remediation-score-track {
                background: rgba(128,128,128,0.2);
                border-radius: 999px;
                display: block;
                height: 0.42rem;
                overflow: hidden;
            }
            .remediation-score-track span {
                background: #378add;
                border-radius: inherit;
                display: block;
                height: 100%;
            }
            .remediation-detail-card {
                border: 1px solid rgba(128,128,128,0.2);
                border-radius: 12px;
                display: none;
                margin-top: 0.5rem;
                padding: 1rem 1.25rem;
            }
            .remediation-detail-head {
                align-items: center;
                border-bottom: 1px solid rgba(128,128,128,0.15);
                display: flex;
                gap: 0.75rem;
                margin-bottom: 0.9rem;
                padding-bottom: 0.9rem;
            }
            .remediation-initials {
                align-items: center;
                background: rgba(28,131,225,0.12);
                border-radius: 8px;
                color: rgb(28,131,225);
                display: flex;
                flex: 0 0 auto;
                font-size: 0.84rem;
                font-weight: 600;
                height: 2.3rem;
                justify-content: center;
                width: 2.3rem;
            }
            .remediation-detail-title {
                font-size: 0.96rem;
                font-weight: 600;
            }
            .remediation-muted {
                color: rgba(250,250,250,0.58);
                font-size: 0.82rem;
            }
            .remediation-detail-priority {
                border-radius: 999px;
                font-size: 0.74rem;
                font-weight: 700;
                padding: 0.12rem 0.54rem;
            }
            .remediation-detail-metrics {
                display: grid;
                gap: 0.65rem;
                grid-template-columns: repeat(4, minmax(0, 1fr));
                margin-bottom: 1rem;
            }
            .remediation-detail-metrics div {
                background: rgba(128,128,128,0.08);
                border-radius: 8px;
                padding: 0.8rem;
            }
            .remediation-detail-metrics small,
            .remediation-detail-metrics strong {
                display: block;
            }
            .remediation-detail-metrics small {
                color: rgba(250,250,250,0.58);
                margin-bottom: 0.2rem;
            }
            .remediation-detail-metrics strong {
                font-size: 1.18rem;
                font-variant-numeric: tabular-nums;
            }
            .remediation-detail-kev {
                color: #ff5b61;
            }
            .remediation-top-cves {
                margin-bottom: 0.45rem;
            }
            .remediation-cve-tags {
                display: flex;
                flex-wrap: wrap;
                gap: 0.42rem;
            }
            .remediation-cve-tag {
                background: rgba(128,128,128,0.1);
                border: 1px solid rgba(128,128,128,0.2);
                border-radius: 6px;
                font-family: monospace;
                font-size: 0.78rem;
                padding: 0.22rem 0.62rem;
            }
            @media (max-width: 700px) {
                .remediation-detail-metrics {
                    grid-template-columns: repeat(2, minmax(0, 1fr));
                }
            }
            .remediation-picker:not(:has(.remediation-target:target)) .remediation-row-0 {
                background: rgba(28,131,225,0.18);
            }
            .remediation-picker:not(:has(.remediation-target:target)) .remediation-detail-0 {
                display: block;
            }
            """ + "\n".join(_selection_css) + """
            </style>
            """,
            unsafe_allow_html=True,
        )
        st.markdown(
            '<div class="remediation-picker">'
            + "".join(_action_targets)
            + '<div class="remediation-table-shell"><table class="remediation-table">'
            '<thead><tr><th>#</th><th>Vendor</th><th>Product</th><th>CVEs</th>'
            '<th>KEV</th><th>Max priority</th><th>Mean EPSS</th><th>Action score</th>'
            '</tr></thead><tbody>'
            + "".join(_table_rows)
            + '</tbody></table></div><div class="remediation-details">'
            + "".join(_detail_cards)
            + "</div></div>",
            unsafe_allow_html=True,
        )

    with strategy_tab:
        st.caption(
            "Top 50 vulnerabilities selected by each capacity strategy. "
            "This view comes straight from the capacity simulation output."
        )

        _strategy_labels = {
            "top_priority": "Top priority",
            "high_epss": "High EPSS",
            "cluster_based": "Cluster based",
            "kev_first": "KEV first",
            "hybrid": "Hybrid",
        }

        strategy = st.selectbox(
            "Strategy",
            list(_strategy_labels),
            format_func=lambda value: _strategy_labels.get(value, value.replace("_", " ").title()),
            key="rem_capacity_strategy",
        )

        recommendations = remediation_recommendations(strategy, top_n=50, snapshot_date=snapshot_date)
        if _no_data(recommendations, "Capacity-strategy recommendations not yet generated."):
            st.info("Capacity-strategy recommendations are not yet available for this snapshot.")
        else:
            summary = strategy_comparison(snapshot_date)
            summary_row = summary[summary["strategy"] == strategy] if not summary.empty else pd.DataFrame()

            if not summary_row.empty:
                row = summary_row.iloc[0]
                kev_coverage = float(row.get("kev_coverage", 0) or 0)
                epss_mitigated = float(row.get("epss_expected_mitigated", 0) or 0)
                cluster_diversity = float(row.get("cluster_diversity", 0) or 0)
                selected_count = int(row.get("n_selected", 0) or 0)

                def _strategy_card(title: str, value: str, subtitle: str, accent: str) -> str:
                    return f"""
<div style="border:1px solid rgba(128,128,128,0.2);border-radius:14px;padding:14px 15px;background:var(--background-color);box-shadow:0 1px 0 rgba(0,0,0,0.04);">
  <div style="font-size:12px;letter-spacing:.02em;text-transform:uppercase;color:gray;margin-bottom:8px;">{escape(title)}</div>
  <div style="font-size:1.45rem;font-weight:700;line-height:1.1;color:{accent};margin-bottom:6px;">{escape(value)}</div>
  <div style="font-size:12px;color:gray;">{escape(subtitle)}</div>
</div>
"""

                _metric_grid = (
                    '<div style="display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin:0.5rem 0 1.1rem;">'
                    + _strategy_card("KEV coverage", f"{kev_coverage:.0%}", "Share of KEV CVEs captured by the strategy", "#d14b4b")
                    + _strategy_card("EPSS mitigated", f"{epss_mitigated:.2f}", "Cumulative EPSS score selected", "#00a3a3")
                    + _strategy_card("Cluster diversity", f"{cluster_diversity:.2f}", "Entropy-style spread across clusters", "#7d7dff")
                    + _strategy_card("Selected CVEs", f"{selected_count:,}", "Rows selected under the current capacity", "#cc7a00")
                    + '</div>'
                )
                st.markdown(_metric_grid, unsafe_allow_html=True)
            else:
                st.info("Strategy summary metrics are not yet available for this snapshot.")

            display_cols = [c for c in [
                "cve_id",
                "priority_score_final",
                "epss_score",
                "is_kev",
                "cvss_score",
                "cluster_id",
                "primary_vendor",
                "primary_product",
            ] if c in recommendations.columns]
            export_cols = [c for c in [
                *display_cols,
                "priority_level_final",
                "cvss_severity",
            ] if c in recommendations.columns]

            export_name = f"capacity_strategy_{strategy}_{snapshot_date or 'latest'}.csv"
            st.download_button(
                "Export CSV",
                data=recommendations[export_cols].to_csv(index=False).encode("utf-8"),
                file_name=export_name,
                mime="text/csv",
                use_container_width=True,
            )

            max_priority_score = float(recommendations["priority_score_final"].max() or 1.0) if "priority_score_final" in recommendations.columns else 1.0

            def _fmt_cell(value, digits: int = 2) -> str:
                try:
                    return f"{float(value):.{digits}f}"
                except (TypeError, ValueError):
                    return "—"

            _P_COLOR = {"Critical": "#c0282a", "High": "#c96e00",
                        "Medium": "#a07d00", "Low": "#1d831d"}
            _P_BG = {
                "Critical": "rgba(214,39,40,0.16)",
                "High": "rgba(255,127,14,0.16)",
                "Medium": "rgba(200,155,0,0.16)",
                "Low": "rgba(44,160,44,0.16)",
            }

            _rows_html = []
            for idx, row in recommendations.reset_index(drop=True).iterrows():
                cve_id = escape(str(row.get("cve_id", "") or ""))
                priority_score = float(row.get("priority_score_final", 0) or 0)
                epss_score = float(row.get("epss_score", 0) or 0)
                is_kev = int(row.get("is_kev", 0) or 0)
                cvss_score = _fmt_cell(row.get("cvss_score"), 1)
                cluster_id = row.get("cluster_id")
                cluster_text = "—" if pd.isna(cluster_id) else str(int(cluster_id))
                vendor = escape(str(row.get("primary_vendor", "") or "—"))
                product = escape(str(row.get("primary_product", "") or "—"))
                priority_level = str(row.get("priority_level_final") or "")
                priority_color = _P_COLOR.get(priority_level, "gray")
                priority_bg = _P_BG.get(priority_level, "rgba(128,128,128,0.12)")
                kev_badge = (
                    '<span style="display:inline-flex;align-items:center;padding:0.22rem 0.55rem;'
                    'border-radius:999px;background:rgba(255,91,97,0.14);color:#ff5b61;'
                    'font-size:12px;font-weight:700;">KEV</span>'
                    if is_kev == 1
                    else '<span style="display:inline-flex;align-items:center;padding:0.22rem 0.55rem;'
                         'border-radius:999px;background:rgba(128,128,128,0.12);color:rgba(250,250,250,0.62);'
                         'font-size:12px;font-weight:700;">No</span>'
                )
                priority_fill = max(0.0, min(100.0, 100.0 * priority_score / max_priority_score)) if max_priority_score else 0.0
                _rows_html.append(
                    f"""
<tr class="remediation-row">
  <td class="remediation-number">{idx + 1}</td>
  <td><strong>{cve_id}</strong></td>
  <td>
    <span class="remediation-badge" style="min-width:4.9rem;color:{priority_color};background:{priority_bg};">
      {escape(priority_level or _priority_label(priority_score))}
    </span>
  </td>
  <td class="remediation-number">{epss_score:.2f}</td>
  <td>{kev_badge}</td>
  <td class="remediation-number">{cvss_score}</td>
  <td class="remediation-number">{cluster_text}</td>
  <td>{vendor}</td>
  <td>{product}</td>
  <td>
    <div style="display:grid;gap:0.25rem;grid-template-columns:minmax(4.5rem, 1fr) auto;align-items:center;">
      <div style="background:rgba(128,128,128,0.2);height:0.4rem;border-radius:999px;overflow:hidden;">
        <div style="width:{priority_fill:.1f}%;height:100%;background:#378add;border-radius:inherit;"></div>
      </div>
      <span style="font-variant-numeric:tabular-nums;">{priority_score:.2f}</span>
    </div>
  </td>
</tr>
"""
                )

            st.markdown(
                '<style>'
                '.strategy-table-shell {'
                '  border: 1px solid rgba(128,128,128,0.24);'
                '  border-radius: 14px;'
                '  max-height: 420px;'
                '  overflow: auto;'
                '  margin-top: 0.75rem;'
                '}'
                '.strategy-table {'
                '  width: 100%;'
                '  min-width: 760px;'
                '  border-collapse: collapse;'
                '  font-size: 0.92rem;'
                '}'
                '.strategy-table thead th {'
                '  background: rgba(128,128,128,0.12);'
                '  color: rgba(250,250,250,0.72);'
                '  padding: 0.82rem 0.7rem;'
                '  text-align: left;'
                '  white-space: nowrap;'
                '  font-weight: 600;'
                '}'
                '.strategy-table tbody td {'
                '  border-top: 1px solid rgba(128,128,128,0.16);'
                '  padding: 0.72rem 0.7rem;'
                '  vertical-align: middle;'
                '}'
                '.strategy-table tbody tr:hover {'
                '  background: rgba(28,131,225,0.08);'
                '}'
                '.strategy-number {'
                '  text-align: right;'
                '  font-variant-numeric: tabular-nums;'
                '}'
                '</style>',
                unsafe_allow_html=True,
            )
            st.markdown(
                '<div class="strategy-table-shell"><table class="strategy-table">'
                '<thead><tr>'
                '<th>#</th>'
                '<th>CVE</th>'
                '<th>Priority band</th>'
                '<th>EPSS</th>'
                '<th>KEV</th>'
                '<th>CVSS</th>'
                '<th>Cluster</th>'
                '<th>Vendor</th>'
                '<th>Product</th>'
                '<th>Priority score</th>'
                '</tr></thead><tbody>'
                + "".join(_rows_html)
                + '</tbody></table></div>',
                unsafe_allow_html=True,
            )
