------------------------------------------------------------------------

editor_options: markdown: wrap: 72 ---

# Vulnerability Intelligence Platform — Implementation Plan

This document is the single source of truth for refactoring the project. It is organized so each teammate can pick a slice of work, hand the relevant section to Claude (using the prompt template at the end), and produce production-quality code that fits the rest of the system.

------------------------------------------------------------------------

## 1. Project context

We are building a platform that ingests public vulnerability disclosures and helps organizations prioritize remediation under limited operational capacity. The brief asks for four capabilities:

1.  **Cluster related issues** — group similar vulnerabilities to see families.
2.  **Estimate likely impact** — score each vulnerability by severity and exploit risk.
3.  **Track exploitability signals** — incorporate active-exploit and probabilistic signals over time.
4.  **Rank remediation actions under limited operational capacity** — produce an actionable patch plan that respects team throughput.

The deliverable must be a Big Data system: a real medallion pipeline on Spark, defensible storage choices, measurable goals, and a results layer the user can interact with.

### Data sources (real, public)

| Source | Format | Update frequency | Volume (12y window) | Role |
|----|----|----|----|----|
| **NVD** (NIST National Vulnerability Database) | gzipped JSON, yearly feeds | Yearly feeds: daily / `recent` and `modified`: every 2 h | \~250-300 K CVEs | Authoritative CVE catalog with CVSS, CWE, CPE |
| **CISA KEV** (Known Exploited Vulnerabilities) | CSV, single snapshot | Weekdays, US business hours, ad-hoc | \~1.5 K CVEs cumulative | Ground-truth flag for actively-exploited vulnerabilities |
| **EPSS** (Exploit Prediction Scoring System) | gzipped CSV, daily snapshot | Once per day | \~250 K rows per snapshot | Probabilistic exploit-likelihood score |

### Big Data justification (must appear in the README)

- **Variety**: three sources with different formats (multiline nested JSON, flat CSV, gzipped CSV) and different semantics (catalog, ranking, ground truth).
- **Volume**: 12 years × growing rate \~ 250-300 K CVEs; full join in the gold layer is in the millions of rows once history of EPSS is kept.
- **Velocity**: NVD `modified` feed updates every 2 h, EPSS daily, KEV ad-hoc. The system runs as a daily batch pipeline launched manually or by cron.

### Why not Kafka

All three sources publish at human-readable batch cadences (≥ 2 h). Volumes per day are tiny (≈ 250 new CVEs, ≈ 1 KEV, 1 EPSS snapshot). Kafka would be an anti-pattern. The README must argue this explicitly and mention the realistic future case where Kafka would be justified (asset-detection telemetry from internal scanners, GHSA webhooks).

### Why DuckDB as the serving layer

The Streamlit app and the analysis notebooks need SQL access over the gold-layer Parquet without paying for an ETL into a server-based database. DuckDB queries Parquet files directly (with predicate pushdown over our partitions), is embedded (no service to run), and uses \~80 MB only when a query is executing. We get a clean compute-vs-serving separation without duplicating data.

### Why cron for orchestration

The pipeline has a real dependency order (NVD/KEV/EPSS ingestion, then join, then scoring/clustering, then simulation). For this single-node academic setup, `src/pipeline/daily_pipeline.py` keeps that order explicit and cron can launch it daily without adding an always-on scheduler next to Spark.

### Constraints

- Development laptop has **8 GB RAM**. Spark must be tuned for single-node low memory.
- Local mode only (`local[*]`). Executor memory is irrelevant; only `driver.memory` matters.
- We process NVD **year by year** (not all years at once) and write partitioned Parquet.
- All paths are centralized in `src/config.py`. No hardcoded paths in scripts.

------------------------------------------------------------------------

## 2. Architecture (target state)

```         
┌──────────────────────────────────────────────────────────────────────┐
│                         Orchestration                                 │
│  src/pipeline/daily_pipeline.py (manual run or cron schedule)         │
└──────────────────────────────────────────────────────────────────────┘
                │
                ▼
┌────────────┐  ┌────────────┐  ┌────────────┐
│ ingest_nvd │  │ ingest_kev │  │ ingest_epss│   parallel ingestion
└─────┬──────┘  └─────┬──────┘  └─────┬──────┘
      │               │                │
      ▼               ▼                ▼
┌──────────────────────────────────────────────┐
│        data/raw/    (gz, json, csv)          │
└──────────────────────────────────────────────┘
                │
                ▼
┌──────────────────────────────────────────────┐
│        data/silver/ (clean Parquet)          │
│  nvd  (partition: year)                      │
│  kev                                          │
│  epss (partition: score_date)                │
└──────────────────────────────────────────────┘
                │
                ▼
        join_master  ──────────►  data_quality (metrics → gold)
                │
                ▼
┌──────────────────────────────────────────────┐
│  data/gold/master_vulnerabilities/           │
│  (partition: published_year, snapshot_date)  │
└──────────────────────────────────────────────┘
                │
                ▼
        priority_scoring (base score)
                │
                ▼
        clustering (TF-IDF + CWE + vendor mixed features)
                │
                ▼
        cluster_aware_scoring   ←── enriches base score with cluster signals
                │
                ▼
        capacity_simulation
                │
                ▼
┌──────────────────────────────────────────────┐
│  data/gold/                                  │
│   vulnerability_scores/                      │
│   vulnerabilities_clustered/                 │
│   cluster_risk_summary/                      │
│   strategy_comparison/                       │
│   remediation_recommendations/               │
│   remediation_actions/   ← actionable list   │
│   data_quality/                              │
└──────────────────────────────────────────────┘
                │
                ▼
       DuckDB  ◄──── Streamlit app
```

### Master schema — the integration contract

The gold-layer `master_vulnerabilities` table is the contract between Person A's ingestion work and Person B and C's analytics work. The schema below is final: B and C should treat every column as input and must not depend on intermediate silver-layer columns directly. Defaults are already applied (`is_kev=0`, `is_ransomware=false`, `epss_score=0.0`) so downstream code does not need defensive `coalesce`/`fillna` calls.

| Column | Type | Source | Person B uses for | Person C uses for |
|----|----|----|----|----|
| **Identity & partitioning** |  |  |  |  |
| `cve_id` | string | NVD | join key | display key, grouping |
| `published` | timestamp | NVD | `days_since_published` feature | temporal filters |
| `last_modified` | timestamp | NVD | — | CVE detail view |
| `published_year` | int | derived | data_quality (temporal trends) | — |
| `snapshot_date` | date | job stamp | "latest snapshot" filter | app default filter |
| **Description & taxonomy** |  |  |  |  |
| `description` | string | NVD | **clustering input (TF-IDF)** | CVE detail view |
| `cwes` | array\<string\> | NVD | **one-hot CWE features in clustering**, top-CWEs in `cluster_topics` | top CWEs per cluster (Streamlit) |
| **Severity (CVSS, with v4→v3.1→v3.0→v2 fallback)** |  |  |  |  |
| `cvss_score` | double | NVD | **base score component (40% weight)** | simulator metric |
| `cvss_severity` | string | NVD | data_quality (distribution) | filter + badge in app |
| `cvss_version` | string | NVD | data_quality (audit fallback) | — |
| **Affected products (NVD CPE)** |  |  |  |  |
| `cpe_vendors` | array\<string\> | NVD | **one-hot top-30 vendors in clustering** | — |
| `cpe_products` | array\<string\> | NVD | data_quality (CPE coverage) | — |
| `cpe_versions` | array\<string\> | NVD | — | — (informational, future) |
| **Exploitability signals (NVD references + KEV)** |  |  |  |  |
| `reference_count` | int | NVD | data_quality | — |
| `has_exploit_reference` | boolean | NVD | optional scoring feature | filter in explorer |
| `is_kev` | int 0/1 | KEV | **score override (floor 0.9)**, `cluster_kev_density` aggregate | **`kev_first` strategy**, `kev_coverage` metric |
| `kev_date_added` | date | KEV | data_quality (KEV timeline) | display in detail |
| `is_ransomware` | boolean | KEV derived | optional scoring feature | badge in app |
| `known_ransomware_campaign_use` | string | KEV | — | literal display |
| `kev_vulnerability_name` | string | KEV | — | human-readable title in remediation_actions |
| `kev_short_description` | string | KEV | — | explorer view |
| `kev_required_action` | string | KEV | — | action text in remediation plan |
| `kev_vendor`, `kev_product` | string | KEV | — | already used as fallback in `primary_*` |
| **Probability of exploitation (EPSS, latest snapshot)** |  |  |  |  |
| `epss_score` | double (0 if null) | EPSS | **score component**, `cluster_epss_max` aggregate | **`high_epss` strategy**, `epss_expected_mitigated` metric |
| `epss_percentile` | double (0 if null) | EPSS | preferred over raw score (more stable day-to-day) | — |
| `epss_score_date` | date | EPSS | data_quality (snapshot freshness) | — |
| **Derived for downstream grouping** |  |  |  |  |
| `primary_vendor` | string | NVD CPE first → KEV fallback | — | **`groupBy` key in remediation_actions** |
| `primary_product` | string | NVD CPE first → KEV fallback | — | **`groupBy` key in remediation_actions** |

#### What this contract gives you (B and C)

- **No defensive null handling.** `is_kev=0`, `is_ransomware=False`, `epss_score=0.0`, `epss_percentile=0.0` are guaranteed defaults. Empty arrays (`cwes`, `cpe_*`) may be empty, but never null in semantically wrong ways — `len() = 0` is the safe check.
- **Vendor/product grouping is solved.** `primary_vendor` and `primary_product` already encode the NVD-first / KEV-fallback rule. Person C builds `remediation_actions` straight on top with `df.groupBy("primary_vendor", "primary_product")` and never has to touch the raw CPE arrays.
- **Partition pruning is free.** Filter on `published_year` or `snapshot_date` and Spark / DuckDB skip the rest.
- **Historical EPSS lives in silver, not master.** The master holds only the latest EPSS snapshot per `cve_id`. If a downstream job needs the history (e.g., to detect rising EPSS scores), it reads `data/silver/epss/` directly.

#### Validated coverage on the 12-year run

Numbers from the smoke test against \~273 K rows (2015–2026):

| Metric                 |                                Actual | README target |
|------------------------|--------------------------------------:|--------------:|
| Total rows             |                               272,962 |             — |
| \% CVEs with CVSS      |                                 94.0% |        \> 95% |
| \% CVEs with EPSS \> 0 |                                 94.7% |        \> 90% |
| \% CVEs with NVD CPE   |                                 82.3% |             — |
| KEV CVEs in master     |                                 1,433 |             — |
| CVSS version mix       | v3.1 68% / v3.0 15% / v4.0 9% / v2 2% | all 4 visible |

The CVSS-fallback chain is exercised in production: 9 % of CVEs use v4, 2 % fall all the way to v2. This is the data quality story for the "track exploitability signals" pillar of the brief.

------------------------------------------------------------------------

### Final repository layout

```         
Big-Data-Technologies-Project/
├── README.md
├── requirements.txt
├── .gitignore
├── IMPLEMENTATION_PLAN.md              ← this file
├── src/
│   ├── __init__.py
│   ├── config.py                        ← central paths + Spark session
│   ├── ingestion/
│   │   ├── __init__.py
│   │   ├── ingest_nvd.py
│   │   ├── ingest_kev.py
│   │   └── ingest_epss.py
│   ├── processing/
│   │   ├── __init__.py
│   │   ├── join_master.py
│   │   └── data_quality.py             ← NEW
│   ├── scoring/
│   │   ├── __init__.py
│   │   ├── priority_scoring.py
│   │   └── cluster_aware_scoring.py    ← NEW
│   ├── clustering/
│   │   ├── __init__.py
│   │   └── clustering.py
│   ├── optimization/
│   │   ├── __init__.py
│   │   ├── capacity_simulation.py
│   │   └── remediation_actions.py      ← NEW
│   ├── pipeline/
│   │   ├── __init__.py
│   │   └── daily_pipeline.py
│   └── utils/
│       ├── __init__.py
│       ├── http.py                      ← NEW: download w/ retries
│       └── duckdb_helpers.py            ← NEW: SQL helpers for app/notebooks
├── app/
│   └── streamlit_app.py                 ← currently empty, full rewrite
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── test_priority_scoring.py
│   ├── test_join_master.py
│   ├── test_cluster_aware_scoring.py
│   └── test_remediation_actions.py
└── data/
    ├── raw/
    │   ├── nvd/
    │   ├── nvd_json/
    │   ├── kev/
    │   └── epss/
    ├── silver/
    │   ├── nvd/year=YYYY/
    │   ├── kev/
    │   └── epss/score_date=YYYY-MM-DD/
    └── gold/
        ├── master_vulnerabilities/published_year=YYYY/snapshot_date=YYYY-MM-DD/
        ├── data_quality/
        ├── vulnerability_scores/
        ├── vulnerabilities_clustered/
        ├── clustering_metrics/
        ├── cluster_risk_summary/
        ├── strategy_comparison/
        ├── remediation_recommendations/{top_priority,high_epss,cluster_based,kev_first,hybrid}/
        └── remediation_actions/
```

> Note: the `data/prod/` and `data/dev/` directories are removed; we work with a single `data/` tree.

------------------------------------------------------------------------

## 3. Work breakdown by file

Each file below has: **purpose**, **change type** (NEW / MODIFY / DELETE), **owner suggestion**, **detailed change list**, and **acceptance criteria**.

------------------------------------------------------------------------

### 3.1 New files

#### `src/config.py` — NEW — Owner: A (infra)

**Purpose.** Centralize all paths and the Spark session factory. Every script imports from here; nothing else hardcodes a path or a Spark config.

**Required contents.**

- Constants for every directory under `data/raw/`, `data/silver/`, `data/gold/`.
- `DEFAULT_NVD_YEARS = list(range(2015, 2027))` (12-year window).
- Function `create_spark_session(app_name: str, driver_memory: str = "3g") -> SparkSession` that produces a session tuned for an 8 GB single-node machine:
  - `spark.driver.memory`: parameter, default `"3g"`.
  - `spark.driver.maxResultSize`: `"1g"`.
  - `spark.sql.shuffle.partitions`: `"8"`.
  - `spark.sql.adaptive.enabled`: `"true"`.
  - `spark.sql.adaptive.coalescePartitions.enabled`: `"true"`.
  - `spark.serializer`: `"org.apache.spark.serializer.KryoSerializer"`.
  - `spark.memory.fraction`: `"0.6"`.
  - `setLogLevel("WARN")`.
- Function `get_snapshot_date() -> str` returning today as `YYYY-MM-DD`.

**Acceptance.** All other modules import `create_spark_session` and the path constants from this module and contain zero string literals for data paths.

------------------------------------------------------------------------

#### `src/utils/http.py` — NEW — Owner: A (infra)

**Purpose.** A single `download_file(url, output_path, force=False)` helper with retries (use `tenacity`: 3 attempts, exponential backoff 2–10 s, retry on `requests.RequestException` and HTTP 5xx). Replaces the inline `download_file` duplicated in three ingestion scripts.

**Acceptance.** All three ingestion scripts import this helper instead of defining their own.

------------------------------------------------------------------------

#### `src/utils/duckdb_helpers.py` — NEW — Owner: D (analytics)

**Purpose.** Thin convenience layer around DuckDB so the Streamlit app keeps query patterns consistent and testable in one place.

**Required contents.**

- `get_connection() -> duckdb.DuckDBPyConnection` (in-memory, registers no tables).
- `query_parquet(sql: str, **params) -> pd.DataFrame` that runs SQL against `data/gold/**/*.parquet` paths declared in `src/config.py`. All Streamlit queries go through this function — no `pd.read_parquet` calls in the app.
- Pre-defined view templates:
  - `top_n_vulnerabilities(n=50, min_priority=0.0, only_kev=False, vendor=None)`.
  - `cluster_overview()`.
  - `strategy_comparison()`.
  - `remediation_actions(top_n=50)`.

**Acceptance.** App and notebooks call these helpers; no raw `pd.read_parquet` calls remain in user-facing code.

------------------------------------------------------------------------

#### `src/processing/data_quality.py` — NEW — Owner: C (processing)

**Purpose.** Compute and persist data-quality metrics. The brief explicitly asks for "assess data quality issues"; we materialize this as a job whose output the Streamlit dashboard surfaces.

**Required contents.**

- Reads `data/gold/master_vulnerabilities/`.
- Computes per snapshot:
  - row count, distinct CVE count
  - \% null per column (cvss_score, epss_score, cwe, vendor_project, product, cpe)
  - severity distribution (Critical/High/Medium/Low/None)
  - intersection sizes: `|NVD ∩ KEV|`, `|NVD ∩ EPSS|`, `|NVD ∩ KEV ∩ EPSS|`
  - mean / median EPSS, % EPSS \> 0.7, % EPSS \> 0.9
  - KEV by year added
- Writes to `data/gold/data_quality/snapshot_date=YYYY-MM-DD/` as Parquet.

**Acceptance.** Job runs without error after `join_master` and produces the expected partition. Output is consumable from DuckDB.

------------------------------------------------------------------------

#### `src/scoring/cluster_aware_scoring.py` — NEW — Owner: C (processing)

**Purpose.** Implement the sandwich scoring step. After clustering, compute cluster-level signals and produce a refined `priority_score_final` per CVE.

**Required contents.**

- Reads `data/gold/vulnerabilities_clustered/`.
- Per-cluster aggregates: `cluster_size`, `cluster_kev_density` (mean of `is_kev`), `cluster_epss_max`, `cluster_epss_mean`, `cluster_avg_cvss`.
- Joins back and produces:
  - `priority_score_final = priority_score * (1 + alpha * cluster_kev_density) + beta * cluster_epss_max`
  - Default `alpha=0.5`, `beta=0.1`, both `argparse`-overridable.
  - Clip to `[0, 1.5]`.
- Recomputes `priority_level_final` with the same thresholds as the base level.
- Writes to `data/gold/vulnerability_scores_final/snapshot_date=YYYY-MM-DD/`.

**Acceptance.** Output has both `priority_score` and `priority_score_final`. Documented in the README so the discrepancy between the two is explicit.

------------------------------------------------------------------------

#### `src/optimization/remediation_actions.py` — NEW — Owner: D (analytics)

**Purpose.** Convert the per-CVE ranking into an actionable list of remediation actions grouped by `(vendor_project, product)`. This is the "rank remediation actions" pillar of the brief, in the form a security engineer would actually use.

**Required contents.**

- Reads `data/gold/vulnerability_scores_final/` (latest snapshot).
- Groups by `(vendor_project, product)` (rows without CPE go to a synthetic group `unknown`).
- Per group computes:
  - `n_cves` (total CVEs covered if you patch this product)
  - `n_kev` (how many of those are in KEV)
  - `max_priority`, `sum_priority`, `mean_epss`, `max_epss`
  - `effort_proxy = log(1 + n_cves)` (more CVEs ≈ more regression risk)
  - `action_score = sum_priority / effort_proxy` (impact per unit of effort)
  - `top_cves` (array of 5 highest-priority CVEs in the group as evidence)
- Sorts descending by `action_score`.
- Writes to `data/gold/remediation_actions/snapshot_date=YYYY-MM-DD/`.

**Acceptance.** Output is a tidy table where each row is a single recommended action with quantified impact, ready to display in Streamlit.

------------------------------------------------------------------------

#### `app/streamlit_app.py` — NEW (currently empty) — Owner: D (analytics)

**Purpose.** End-user-facing exposure layer. Reads from gold via DuckDB.

**Required pages (sidebar navigation).**

1.  **Overview** — KPIs (total CVEs, KEV count, % critical, mean EPSS, last snapshot date), data-quality cards (% null per column, source intersections), severity distribution chart.
2.  **Vulnerability Explorer** — filters: severity, vendor, product, KEV-only, min EPSS, min priority. Sortable table. Detail view per CVE.
3.  **Cluster View** — for each cluster: size, top-5 keywords (from centroid), top-5 vendors, KEV density, sample CVEs. PCA-2D scatter color-coded by cluster.
4.  **Capacity Simulator** — sliders for `daily_capacity` and `simulation_days`. Picks one of: `top_priority`, `high_epss`, `cluster_based`, `kev_first`, `hybrid`. Shows: KEV coverage, EPSS-expected mitigated, cluster diversity, mean time-in-backlog. Comparison chart across strategies.
5.  **Remediation Plan** — table from `remediation_actions/`. Shows ranked actions: vendor, product, n_cves, n_kev, max_priority, action_score, top_cves. Download as CSV button.

**Style.** Use `st.cache_data` on every DuckDB query, plotly or altair for charts.

**Acceptance.** App runs end-to-end with `streamlit run app/streamlit_app.py`, never queries a non-existent gold path, and all pages render with the seeded data.

------------------------------------------------------------------------

#### `tests/` — NEW — Owner: shared (each owner writes tests for their own files)

**Purpose.** Minimum unit tests using `pytest` and a tiny in-memory Spark session. Goal is not 100% coverage; goal is to demonstrate engineering rigor.

**Required tests.**

- `tests/conftest.py`: pytest fixture for a small local Spark session (`local[1]`, 1g memory).
- `tests/test_priority_scoring.py`: tests for `compute_priority_score` (linearity, bounds, KEV override behavior) and `assign_priority_level` (boundary values).
- `tests/test_join_master.py`: tests for `prepare_kev` and `prepare_epss` (null handling, type casting, no row loss).
- `tests/test_cluster_aware_scoring.py`: cluster aggregations sum correctly, refined score is monotone in `cluster_kev_density`.
- `tests/test_remediation_actions.py`: grouping is correct, `action_score` is well-defined, ordering descends.

**Acceptance.** `pytest -q` exits 0.

------------------------------------------------------------------------

#### `README.md` — NEW (currently 1 line) — Owner: A

**Purpose.** First thing the evaluator sees.

**Required sections.**

1.  Title + one-line problem statement.
2.  Architecture diagram (ASCII or PNG generated from Mermaid).
3.  Data sources table with frequencies (copy from Section 1 of this plan).
4.  Big Data justification (variety, volume, velocity).
5.  Trade-offs and choices: why Spark, why Parquet (not Delta), why DuckDB, why not Kafka, why cron.
6.  Repository layout.
7.  How to run: requirements, environment setup, single-command pipeline run, Streamlit launch, cron scheduling.
8.  Measurable goals (set targets for KEV coverage, pipeline runtime, data-quality thresholds, etc.).
9.  Limitations and future work.
10. Team and division of work.

**Acceptance.** README is self-contained: a teacher who has never seen the project understands what it does, why those technologies, and how to run it.

------------------------------------------------------------------------

#### `requirements.txt` — NEW — Owner: A

Pinned versions. Minimum content:

```         
pyspark==3.5.1
pandas==2.2.2
numpy==1.26.4
pyarrow==15.0.2
requests==2.32.3
tenacity==8.5.0
duckdb==1.0.0
streamlit==1.36.0
plotly==5.22.0
scikit-learn==1.5.0
pytest==8.2.2
```

------------------------------------------------------------------------

#### `.gitignore` — NEW — Owner: A

Must exclude `data/`, `__pycache__/`, `.ipynb_checkpoints/`, `.DS_Store`, `.vscode/`, `*.parquet`, `*.crc`, `logs/`, `venv/`, `.env`.

------------------------------------------------------------------------

### 3.2 Files to modify

#### `src/ingestion/ingest_nvd.py` — MAJOR — Owner: B (ingestion)

**What changes.**

1.  Import `create_spark_session` and `download_file` from new shared modules.
2.  Process **year by year**: load one JSON, transform, write partition `data/silver/nvd/year=YYYY/`, drop in-memory DataFrame, move to next year. Do **not** load all years at once.
3.  CVSS extraction with fallback chain: prefer v4.0, then v3.1, then v3.0, then v2. Add a `cvss_version` column recording which one was used.
4.  Extract **CWE list** (concatenate all CWEs into an array column `cwes`), not just the first.
5.  Extract **CPE info**: parse `configurations.nodes.cpeMatch[*].criteria` (CPE 2.3 string), derive `vendor`, `product`, and `version_range` arrays.
6.  Extract **references**: count of references and a boolean `has_exploit_reference` (any reference tagged `Exploit`).
7.  Cast `published` and `lastModified` to `TimestampType`.
8.  Add `published_year` derived column for downstream partitioning.
9.  Add `--years` argument that defaults to the constant from `src/config.py`.
10. Replace inline `download_file` with the helper from `src/utils/http.py`.

**Acceptance.** Output silver schema: `cve_id, published, last_modified, published_year, description, cwes (array<string>), cvss_score, cvss_severity, cvss_version, cpe_vendors (array<string>), cpe_products (array<string>), reference_count, has_exploit_reference`. Year-partitioned. No `print()` statements left in module-level code; use `logging`.

------------------------------------------------------------------------

#### `src/ingestion/ingest_kev.py` — MEDIUM — Owner: B

**What changes.**

1.  Use shared `create_spark_session` and `download_file`.
2.  Keep `vendor_project`, `product`, `vulnerability_name` in the silver schema (currently dropped downstream).
3.  Cast `kev_date_added` to `DateType`.
4.  Default `force_download=False`; argparse only has `--force-download` (no `--skip-download` that inverts logic).
5.  Add `is_ransomware` boolean derived from `known_ransomware_campaign_use`.

**Acceptance.** Output silver schema includes all KEV fields. Date is a real `DateType`. CLI flags are consistent with the other two ingestions.

------------------------------------------------------------------------

#### `src/ingestion/ingest_epss.py` — MEDIUM — Owner: B

**What changes.**

1.  Use shared `create_spark_session` and `download_file`.
2.  Write to `data/silver/epss/score_date=YYYY-MM-DD/` (partitioned, do not overwrite). New snapshots accumulate.
3.  Cast `epss_score` and `epss_percentile` to `DoubleType` (already done) and add `score_date` literal column.
4.  `--keep-history` flag (default `True`) to not blindly overwrite older partitions.

**Acceptance.** After running on three different days, the silver folder contains three `score_date=...` partitions and queries can read them all with a single `spark.read.parquet("data/silver/epss/")`.

------------------------------------------------------------------------

#### `src/processing/join_master.py` — MEDIUM — Owner: C

**What changes.**

1.  Use shared `create_spark_session` and config paths.
2.  Read EPSS using **the latest `score_date` partition only** for the master snapshot.
3.  Keep CPE arrays, vendor, product, CWE list from NVD; keep `vendor_project`, `product`, `is_ransomware` from KEV.
4.  When NVD CPE vendor is missing, fall back to KEV `vendor_project` so downstream grouping works.
5.  Add a `snapshot_date` literal column = today.
6.  Write to `data/gold/master_vulnerabilities/published_year=YYYY/snapshot_date=YYYY-MM-DD/`.

**Acceptance.** Output schema is the union of NVD + KEV + EPSS fields, partitioned by `published_year` and `snapshot_date`. Re-running the same day overwrites only that day's partition (`partitionOverwriteMode=dynamic`).

------------------------------------------------------------------------

#### `src/scoring/priority_scoring.py` — MEDIUM — Owner: C

**What changes.**

1.  Use shared `create_spark_session` and config paths.
2.  Add `days_since_published` feature.
3.  Use `epss_percentile` (more stable across days than raw `epss_score`).
4.  **KEV override**: if `is_kev = 1`, force `priority_score = max(score, 0.9)`.
5.  Add CLI flags for the four weights (`cvss`, `epss_percentile`, `kev`, `recency`).
6.  Write `snapshot_date` column. Partition output by `snapshot_date`.

**Acceptance.** Sensitivity analysis is reproducible by re-running with different weights; output partitions accumulate by snapshot_date.

------------------------------------------------------------------------

#### `src/clustering/clustering.py` — MAJOR — Owner: D

**What changes.**

1.  Use shared `create_spark_session` and config paths.
2.  Build **mixed features** with `VectorAssembler`:
    - TF-IDF on description (kept).
    - One-hot on top-30 CWEs.
    - One-hot on top-30 vendors.
    - Numeric: `cvss_score`, `epss_percentile`, `is_kev`.
3.  Replace text PCA with reduced TF-IDF dimensions (vocab 500–1000, `min_df=20`) **before** assembling; PCA only over the assembled vector if needed.
4.  Selection of K must combine three metrics: silhouette, Davies-Bouldin (compute manually, no Spark builtin), KMeans `cost` for elbow detection. Final K is whichever has the best **rank average** across the three.
5.  After fitting the final model, compute and persist **top-10 keywords per cluster** by mapping centroid weights back through the TF-IDF vocabulary, plus top-5 vendors and top-5 CWEs per cluster.
6.  Write `data/gold/cluster_topics/` with `(cluster_id, top_keywords array, top_vendors array, top_cwes array, size, kev_count)`.

**Acceptance.** Output cluster sizes are not all in one bucket; top-keywords are interpretable security terms; the chosen K is justified by the combined metric (printed table).

------------------------------------------------------------------------

#### `src/optimization/capacity_simulation.py` — MAJOR — Owner: D

**What changes.**

1.  Use shared `create_spark_session` and config paths.

2.  Read `data/gold/vulnerability_scores_final/` (after `cluster_aware_scoring`), not the base scoring output.

3.  **Replace** `strategy_cluster_based` `union`-loop with a window function:

    ``` python
    from pyspark.sql.window import Window
    from pyspark.sql.functions import row_number
    w = Window.partitionBy("cluster_id").orderBy(col("priority_score_final").desc())
    df.withColumn("rn", row_number().over(w)).filter(col("rn") <= per_cluster).limit(capacity)
    ```

4.  Add two new strategies:

    - `kev_first`: take all KEV CVEs first (sorted by `priority_score_final`), then top by score until capacity is filled.
    - `hybrid`: 50% KEV-first, 50% cluster-balanced.

5.  Replace the single biased metric (`sum(priority_score)`) with **four metrics** per strategy:

    - `kev_coverage = n_kev_selected / n_kev_total`
    - `epss_expected_mitigated = sum(epss_score for selected)` (interpretable as "expected exploits prevented")
    - `cluster_diversity = entropy of cluster distribution among selected`
    - `mean_priority_selected`

6.  **Multi-day simulation**: new function `simulate_multi_day(df, daily_capacity, n_days, arrival_rate)` that simulates `n_days` of operation with `arrival_rate` new CVEs per day, draining the backlog. Outputs daily metrics: `backlog_size`, `kev_in_backlog`, `cumulative_mitigated_epss`, `mean_age_in_backlog`. Writes to `data/gold/simulation_timeseries/`.

7.  CLI flags: `--daily-capacity` (default 50), `--simulation-days` (default 30), `--arrival-rate` (default 50).

**Acceptance.** All five strategies produce comparable metrics; the multi-day output has one row per (day, strategy); the `cluster_based` strategy runs in O(n) without a `union` loop.

------------------------------------------------------------------------

#### `src/pipeline/daily_pipeline.py` — MINOR — Owner: A

**What changes.**

1.  Add new steps to the orchestration in this order:

    ```         
    ingest_nvd → ingest_kev → ingest_epss → join_master → data_quality
    → priority_scoring → clustering → cluster_aware_scoring
    → capacity_simulation → remediation_actions
    ```

2.  Read defaults from `src/config.py` (no hardcoded years/capacity).

3.  Driver memory passed as a single CLI flag, default `"3g"`.

**Acceptance.** A single `python src/pipeline/daily_pipeline.py` runs the full pipeline on a fresh checkout (assuming `data/raw/` already has the downloaded files; otherwise the ingestion steps download them).

------------------------------------------------------------------------

### 3.3 Files and folders to delete

**Delete the entire `notebooks/` folder.** All seven legacy notebooks duplicate the logic in `src/` and the project will not ship any narrative notebooks. The narrative role is covered by the README, the Streamlit app and the written report (memoria) accompanying the project.

```         
notebooks/01_ingest_nvd.ipynb
notebooks/02_ingest_kev.ipynb
notebooks/03_ingest_epss.ipynb
notebooks/04_join_master.ipynb
notebooks/05_priority_scoring.ipynb
notebooks/06_clustering.ipynb
notebooks/07_capacity_simulation.ipynb
```

Run `git rm -r notebooks/` and remove the `notebooks/` entry from any tooling configuration. The `requirements.txt` does **not** include `jupyter` or `notebook`.

Also delete:

- `data/prod/` and `data/dev/` directory trees after moving data to the new flat `data/{raw,silver,gold}/` layout (do this once, with `git mv` or a manual move + commit).

------------------------------------------------------------------------

## 4. Team split (3 people)

This is a binding split. Each owner is responsible for the files in their slice **and** the tests for those files.

### Person A — Infrastructure + Ingestion + Master (\~12 h core) — **lead / blocking dependency**

Files this person owns (must be merged first; B and C cannot start their files until A's `src/config.py` and `src/utils/http.py` are on `main`):

1.  `src/config.py` — central paths and `create_spark_session`.
2.  `src/utils/http.py` — shared `download_file` with `tenacity` retries.
3.  `requirements.txt`.
4.  `.gitignore`.
5.  `README.md` — full rewrite per Section 3.1.
6.  Data folder restructure: move `data/prod/*` to `data/*`, delete `data/prod/` and `data/dev/`.
7.  `src/ingestion/ingest_nvd.py` (MAJOR refactor: year-by-year, CVSS fallback, CPE, references, dates).
8.  `src/ingestion/ingest_kev.py` (MEDIUM: keep more fields, dates, retries).
9.  `src/ingestion/ingest_epss.py` (MEDIUM: snapshot partitioning, retries).
10. `src/processing/join_master.py` (MEDIUM: keep CPE/vendor/product, partitioning, snapshot_date).
11. `src/pipeline/daily_pipeline.py` (MINOR update: new steps, use config).
12. Tests for all files above.

Coordinates with: B on the master schema, C on the gold-layer paths.

### Person B — Data quality + Scoring + Clustering (\~8-10 h)

Files this person owns:

1.  `src/processing/data_quality.py` (NEW).
2.  `src/scoring/priority_scoring.py` (MEDIUM refactor: KEV override, EPSS percentile, days_since_published, sensitivity weights).
3.  `src/scoring/cluster_aware_scoring.py` (NEW: sandwich scoring step).
4.  `src/clustering/clustering.py` (MAJOR refactor: mixed features, K selection by combined metric, top-keywords per cluster).
5.  Tests for all files above.

Coordinates with: A on the gold schema (must agree on column names before B starts), C on the cluster outputs (C's simulator reads B's `vulnerability_scores_final` and `cluster_topics`).

### Person C — Simulation + Remediation + Streamlit (\~10-12 h)

Files this person owns:

1.  `src/optimization/capacity_simulation.py` (MAJOR refactor: Window for cluster_based, two new strategies, four metrics, multi-day simulation).
2.  `src/optimization/remediation_actions.py` (NEW: actionable ranking by vendor+product).
3.  `src/utils/duckdb_helpers.py` (NEW: SQL helpers used by the app).
4.  `app/streamlit_app.py` (NEW: full app with five pages).
5.  Tests for all files above.

Coordinates with: B on the schema of `vulnerability_scores_final` and `cluster_topics`, A on the gold-layer paths.

### Synchronization protocol

- **Day 1**: A merges `src/config.py`, `src/utils/http.py`, `.gitignore`, `requirements.txt`. B and C cannot start their work until this is done.
- **Day 2-3**: A finishes ingestion + join_master. B starts data_quality + priority_scoring (these only depend on the gold schema, which A's join_master defines). C can start `duckdb_helpers.py` and the Streamlit app skeleton against mocked data.
- **Day 4-5**: B finishes clustering + cluster_aware_scoring. C starts the real simulator and remediation_actions against B's output.
- **Day 6**: integration. End-to-end pipeline run by A. C polishes Streamlit against real data.
- **Day 7**: tests + README pass + verification checklist.

------------------------------------------------------------------------

## 5. Prompt template for Claude

When a teammate sits down with Claude in their account, they should attach:

1.  This `IMPLEMENTATION_PLAN.md` file.
2.  The current contents of the file(s) they are responsible for.

Then use the prompt below, filling in the bracketed sections.

------------------------------------------------------------------------

```         
You are helping me implement my slice of a Big Data course project. Read
the attached IMPLEMENTATION_PLAN.md in full before doing anything; it has
the project context, architecture, constraints, and detailed change list.

My slice of work covers the following file(s):
[ list the files from Section 3 you are responsible for ]

For each file, follow the spec under its heading in Section 3 of the plan.
The acceptance criteria listed there are non-negotiable.

Constraints to respect at all times:
- Single-node Spark on local[*], 8 GB RAM machine. Never request more than
  3 GB driver memory. Always create the Spark session via
  `from src.config import create_spark_session`.
- All paths must come from `src.config` constants. No hardcoded paths.
- Use the shared `download_file` from `src.utils.http` (with retries) in any
  module that performs HTTP downloads.
- Output Parquet must be partitioned exactly as specified in the plan.
- Add type hints to every public function. Use `logging` (configured at
  module top) instead of `print()`.
- Each script must be runnable both as a module (`python -m src.x.y`) and
  via `spark-submit`.
- Add a corresponding test under `tests/` for any new function with
  non-trivial logic, using the `spark` fixture from `tests/conftest.py`.

Workflow:
1. Show me the full file diff for each file before writing it.
2. Wait for my approval after each file.
3. After approval, write the file and the corresponding test.
4. At the end, give me a checklist mapping each acceptance criterion in
   Section 3 to the place in the code that satisfies it.

Do not modify files outside my slice. If you think a file outside my slice
needs a change, raise it as a question instead of doing it.

Here are the current contents of my files:

[ paste the current code here ]
```

------------------------------------------------------------------------

## 6. Verification checklist (whole project)

Run before declaring done:

- [ ] `pip install -r requirements.txt` succeeds in a fresh venv.
- [ ] `python src/pipeline/daily_pipeline.py` completes end-to-end on a fresh `data/` directory.
- [ ] All gold-layer paths from the architecture exist and contain data.
- [ ] `pytest -q` passes.
- [ ] `streamlit run app/streamlit_app.py` opens and all five pages render.
- [ ] The `notebooks/` folder no longer exists in the repository.
- [ ] README contains the architecture diagram and the four pillar mappings.
- [ ] No file under `src/` contains a hardcoded data path.
- [ ] No file under `src/` contains a duplicated `create_spark_session` or `download_file`.
- [ ] `git status` shows no `data/` or `__pycache__/` files staged.

------------------------------------------------------------------------

## 7. Out of scope (explicitly)

These are intentionally **not** part of this refactor:

- Kafka or any streaming ingestion.
- Delta Lake / Iceberg (Parquet-only).
- A REST API in front of the gold layer.
- Authentication or multi-user features for the Streamlit app.
- OSV.dev integration (deferred to future work; mention it in the README).
- Distributed Spark (we run local-only).
- Jupyter notebooks. The `notebooks/` folder is removed; narrative goes in the README, the Streamlit app (interactive evidence) and the written report (memoria) accompanying the project.

------------------------------------------------------------------------

End of plan.
