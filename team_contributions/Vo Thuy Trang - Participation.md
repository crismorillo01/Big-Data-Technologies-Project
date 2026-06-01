# Contribution

Focuses on the simulation and optimisation layer, the query interface over the gold layer, and the interactive results dashboard.

## What I own 
 Capacity simulation, remediation ranking, DuckDB helpers, Streamlit dashboard, tests 
`src/optimization/capacity_simulation.py`, `src/optimization/remediation_actions.py`, `src/utils/duckdb_helpers.py`, `app/streamlit_app.py`, `tests/test_remediation_actions.py`

## What Each File Does

`src/optimization/capacity_simulation.py`: mulates five patching strategies under a daily capacity constraint. Computes four metrics per strategy, runs a multi-day simulation with configurable arrival rate, and writes the strategy comparison table, cluster risk summary, remediation recommendations, and simulation timeseries to the gold layer. 
`src/optimization/remediation_actions.py`: Groups CVEs by vendor and product and ranks them by a composite action score. Produces an actionable patch list that a security team can act on directly, rather than a per-CVE list. 
`src/utils/duckdb_helpers.py`:Provides a SQL query interface over the gold-layer Parquet files using DuckDB. Every query in the Streamlit app goes through this module. All functions accept `snapshot_date` so the dashboard can filter every page to the same selected date. 
`app/streamlit_app.py`: Five-page interactive dashboard exposing the full pipeline output to the user. Pages cover the vulnerability overview, the CVE explorer, the cluster view, the capacity simulator, and the remediation plan. The file was empty before this block.
`tests/test_remediation_actions.py`: Nine unit tests covering null normalisation, group counts, KEV counting, action score validity, sort order, evidence CVE bounds, group membership, and the effort proxy formula


### Cluster Risk Summary (`data/gold/cluster_risk_summary/`)

| `cluster_id` | Cluster identifier assigned by the clustering job.
| `cluster_size` | Number of CVEs in the cluster. 
| `avg_priority_final` | Mean cluster-aware final priority score across all CVEs in the cluster. 
| `avg_cvss` | Mean CVSS base score for CVEs in the cluster. 
| `avg_epss` | Mean EPSS score for CVEs in the cluster. 
| `max_epss` | Maximum EPSS score observed in the cluster. 
| `kev_density` | Fraction of CVEs in the cluster that appear in the CISA KEV catalogue. 
| `n_kev` | Absolute count of KEV CVEs in the cluster. 

### Remediation Actions (`data/gold/remediation_actions/`)
`primary_vendor`: Vendor name derived from NVD CPE data, with `unknown` used when CPE is missing. 
`primary_product`: Product name derived from NVD CPE data, with `unknown` used when CPE is missing. 
`n_cves`: Total number of CVEs that would be closed by patching this vendor and product. 
`n_kev`: Number of those CVEs that appear in the CISA KEV catalogue. 
`max_priority`: Highest final priority score among all CVEs in the group. 
`sum_priority`: Sum of final priority scores across all CVEs in the group. Used as the numerator of `action_score`. 
`mean_epss`: Mean EPSS score across all CVEs in the group. 
`max_epss`: Maximum EPSS score observed in the group. 
`effort_proxy`: `log(1 + n_cves)`. Approximates the regression testing and deployment effort required to ship the patch. Larger groups are penalised logarithmically.
`action_score`: `sum_priority / effort_proxy`. Primary sort key. Represents composite impact per unit of effort. 
`top_cves`: Array of up to five CVE IDs with the highest priority score in the group, included as evidence for the recommendation. 
`snapshot_date`: Pipeline execution date, used as the output partition. 

## Five Patching Strategies
`top_priority`: Selects the `daily_capacity` CVEs with the highest `priority_score_final` -> Maximum composite risk score
`high_epss`: Selects the `daily_capacity` CVEs with the highest EPSS score -> Maximum near-term exploitation probability
`cluster_based`: Distributes capacity proportionally across clusters using a `row_number()` window function -> Coverage across vulnerability families
`kev_first`: Fills available slots with KEV CVEs first, then fills remaining slots with top-priority non-KEV CVEs -> Known actively-exploited vulnerabilities
`hybrid`: Allocates 50% of slots to `kev_first` and 50% to `cluster_based`, then deduplicates -> Balance between urgency and coverage

## Dashboard Pages

**Overview** : Total CVEs, KEV count, percentage critical, mean EPSS, severity distribution bar chart, and a two-panel data quality table covering coverage and completeness metrics. |
**Vulnerability Explorer**:  Filterable and sortable table of up to 500 CVEs with filters for priority level, vendor, minimum EPSS, and KEV membership. Includes a CVE detail view showing description, CVSS, EPSS, and required remediation action. |
**Cluster View**: Summary metrics, a sortable cluster risk table, a bubble chart of EPSS vs KEV density sized by cluster size, and expandable cards for the five riskiest clusters. |
**Capacity Simulator**: Strategy comparison table with best-value highlighting, and a multi-day simulation line chart with a selectable metric and strategy highlight. |
**Remediation Plan**: Ranked action table sorted by `action_score`, an evidence CVE expander per action, and a CSV download button. |
