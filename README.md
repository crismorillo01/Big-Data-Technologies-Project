# Vulnerability Intelligence Platform

A Big Data pipeline that ingests public vulnerability disclosures (NVD,
CISA KEV, EPSS), enriches them with cluster-aware risk signals, and
produces a ranked patch plan for security teams operating under limited
remediation capacity.

This is the project for the *Big Data Technologies* course. The full
implementation contract lives in [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md).

---

## What problem does it solve?

A medium-sized organization can have thousands of open CVEs at any time
and a security team that can only ship a few dozen patches per day.
Choosing **which** CVEs to fix first is the entire game. The platform
answers four questions, mapped to the four pillars of the course brief:

1. **Cluster related issues** — group CVEs into families so the team
   sees patterns instead of noise.
2. **Estimate likely impact** — score each CVE by severity (CVSS) and
   exploit risk (EPSS, KEV).
3. **Track exploitability signals** — keep daily EPSS history and KEV
   transitions to detect when something is becoming more dangerous.
4. **Rank remediation actions under limited operational capacity** —
   produce an actionable patch plan that respects the team's daily
   throughput, prefers KEV-flagged CVEs, and groups work by
   `(vendor, product)` so one patch closes many CVEs at once.

---

## Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│ Orchestration                                                       │
│   src/pipeline/daily_pipeline.py    (manual run or cron schedule)   │
└────────────────────────────────────────────────────────────────────┘
                  │
       ┌──────────┼──────────┐
       ▼          ▼          ▼
┌────────────┐┌────────────┐┌────────────┐    parallel ingestion
│ ingest_nvd ││ ingest_kev ││ingest_epss │
└────┬───────┘└──────┬─────┘└──────┬─────┘
     │               │             │
     ▼               ▼             ▼
┌────────────────────────────────────────────────────────────────────┐
│ data/raw/         (.json.gz, .csv, .csv.gz — never modified)        │
└────────────────────────────────────────────────────────────────────┘
     │
     ▼
┌────────────────────────────────────────────────────────────────────┐
│ data/silver/      (clean, typed, partitioned Parquet)               │
│   nvd/year=YYYY/                                                    │
│   kev/                                                              │
│   epss/score_date=YYYY-MM-DD/    ← daily snapshots accumulate       │
└────────────────────────────────────────────────────────────────────┘
     │
     ▼
join_master  ───────────►  data_quality (metrics → gold)
     │
     ▼
┌────────────────────────────────────────────────────────────────────┐
│ data/gold/master_vulnerabilities/                                   │
│   published_year=YYYY/snapshot_date=YYYY-MM-DD/                     │
└────────────────────────────────────────────────────────────────────┘
     │
     ▼
priority_scoring         (base score: CVSS, EPSS, KEV override, recency)
     │
     ▼
clustering               (mixed features: TF-IDF + CWE + vendor + numeric)
     │
     ▼
cluster_aware_scoring    (sandwich step — refines score with cluster signals)
     │
     ▼
capacity_simulation      (5 strategies, multi-day backlog drain, 4 metrics)
     │
     ▼
remediation_actions      (ranked patch plan grouped by (vendor, product))
     │
     ▼
┌────────────────────────────────────────────────────────────────────┐
│ Serving layer                                                       │
│   DuckDB queries Parquet directly (no ETL, no server).              │
│   Streamlit app exposes the results interactively.                  │
└────────────────────────────────────────────────────────────────────┘
```

The data follows a **medallion architecture**: raw is sacred, silver is
typed and partitioned, gold is analytics-ready. Every gold table is
partitioned by `snapshot_date` so historical runs are preserved and
re-running the pipeline only overwrites the current day's partition
(thanks to `spark.sql.sources.partitionOverwriteMode=dynamic`).

---

## Data sources

| Source | Format | Update frequency | Volume (12y window) | Role |
|---|---|---|---|---|
| **NVD** (NIST National Vulnerability Database) | gzipped JSON, yearly feeds | Yearly feeds: daily / `recent` and `modified` feeds: every 2 h | ~250–300 K CVEs | Authoritative CVE catalog with CVSS, CWE, CPE, references |
| **CISA KEV** (Known Exploited Vulnerabilities) | CSV, single snapshot | Weekdays, US business hours, ad-hoc (avg ~1/day) | ~1.5 K CVEs cumulative | Ground-truth flag for actively exploited CVEs |
| **EPSS** (Exploit Prediction Scoring System) | gzipped CSV, daily snapshot | Once per day | ~250 K rows per snapshot | Probabilistic exploit-likelihood score |

All three are public, free and stable.

---

## Big Data justification

This is a real Big Data system, not a small pandas script that says
"big" on the label.

- **Variety** — three sources with very different formats and semantics:
  multi-line nested JSON (NVD, ~150–200 MB per year), flat CSV with
  unstable column names (KEV), and large gzipped CSV (EPSS, ~250 K rows
  daily). Each requires a different parser, schema, and join key.
- **Volume** — 12 years of NVD plus daily-snapshotted EPSS history grows
  the gold layer into the millions of rows quickly. The full join is
  produced in PySpark precisely because pandas would not handle it
  cleanly on the developer's 8 GB RAM laptop.
- **Velocity** — the source with the fastest cadence is the NVD
  `modified` feed at every 2 hours; EPSS is daily; KEV is event-driven
  but rare. We materialize the velocity dimension as a daily batch
  pipeline; the local cron schedule launches the same deterministic
  orchestrator every day.

### Why **not** Kafka

All three sources publish at human-readable batch cadences (≥ 2 h),
with at most ~250 new CVEs and 1 KEV per day. Kafka here would be an
anti-pattern: pure overhead, no benefit. We argue this trade-off
explicitly because the brief asks for "careful trade-offs rather than
trying to build a generic platform for everything." Kafka would be the
right tool the moment we incorporate **asset-detection telemetry** from
internal scanners or **GitHub Security Advisory webhooks** — neither is
in scope today, both are documented as future work.

### Why DuckDB as the serving layer

The Streamlit app needs SQL access to the gold layer without paying for
an ETL into a server-based database. DuckDB queries Parquet files
directly with predicate pushdown over our partitions, runs embedded (no
service to start), and uses ~80 MB RAM only during query execution. We
get a clean compute-vs-serving separation without duplicating data.

### Why plain Parquet (not Delta / Iceberg)

Parquet is enough for this project's scope: read-only consumers, daily
batch writes, no concurrent writers, no schema evolution complexity.
Delta or Iceberg would add ACID transactions, time travel, and upserts
— all genuinely useful in production, but they would also pull a
multi-GB dependency tree and configuration burden disproportionate to
single-node academic work. The trade-off is documented; migration would
be a one-week task on top of the current code.

### Why cron for orchestration

The pipeline has a real dependency order: ingest the public sources,
join the master table, score and cluster vulnerabilities, simulate
capacity, and produce remediation actions. `daily_pipeline.py` keeps
that order explicit in one lightweight command, and cron is enough to
run it once per day on a laptop without adding another always-on service
next to Spark.

---

## Repository layout

```
.
├── README.md                       ← this file
├── IMPLEMENTATION_PLAN.md          ← team contract / file-by-file spec
├── requirements.txt
├── .gitignore
├── src/
│   ├── config.py                   ← every path + Spark session factory
│   ├── ingestion/
│   │   ├── ingest_nvd.py           ← year-by-year, partitioned silver
│   │   ├── ingest_kev.py
│   │   └── ingest_epss.py          ← snapshots accumulate
│   ├── processing/
│   │   ├── join_master.py
│   │   └── data_quality.py         ← metrics → gold
│   ├── scoring/
│   │   ├── priority_scoring.py     ← base score with KEV override
│   │   └── cluster_aware_scoring.py    ← sandwich step
│   ├── clustering/
│   │   └── clustering.py
│   ├── optimization/
│   │   ├── capacity_simulation.py  ← 5 strategies, multi-day
│   │   └── remediation_actions.py  ← ranked patch plan
│   ├── pipeline/
│   │   └── daily_pipeline.py
│   └── utils/
│       ├── http.py                 ← download + retries
│       └── duckdb_helpers.py
├── app/
│   └── streamlit_app.py            ← interactive UI on top of the gold layer
├── tests/
│   └── ...                         ← pytest, small Spark fixture
└── data/                           ← gitignored; created on first run
    ├── raw/
    ├── silver/
    └── gold/
```

---

## Running the pipeline

### Prerequisites

- Python 3.10 or 3.11
- Java 11 or 17 (PySpark requirement; `brew install openjdk@17` on macOS)
- ~8 GB RAM (the Spark session is tuned for this; see `src/config.py`)
- ~2 GB disk for raw + silver + gold across a 12-year window

### Setup

```bash
git clone <repo>
cd Big-Data-Technologies-Project
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### One command, end to end

```bash
python src/pipeline/daily_pipeline.py
```

That runs every step in order. Common overrides:

```bash
# Smaller / faster run (only 2024–2026)
python src/pipeline/daily_pipeline.py --years 2024 2025 2026

# Tighter RAM budget
python src/pipeline/daily_pipeline.py --driver-memory 2g

# Bigger simulation horizon
python src/pipeline/daily_pipeline.py --daily-capacity 30 --simulation-days 60
```

### Running a single step

Every script is independently runnable via `spark-submit`:

```bash
spark-submit src/ingestion/ingest_nvd.py --years 2025 2026
spark-submit src/processing/join_master.py
```

### The Streamlit app

```bash
streamlit run app/streamlit_app.py
```

Opens at `http://localhost:8501` with five pages: Overview, Vulnerability
Explorer, Cluster View, Capacity Simulator, Remediation Plan.

### Daily local scheduling with cron

On macOS/Linux, cron can run the same pipeline every day. Create the
logs directory first:

```bash
mkdir -p logs
```

Then edit the crontab:

```bash
crontab -e
```

Example daily run at 03:00. Replace the placeholder paths with the
absolute paths on the machine that will run the job:

```cron
0 3 * * * export JAVA_HOME=/absolute/path/to/java && export PATH=/absolute/path/to/java/bin:/absolute/path/to/Big-Data-Technologies-Project/.venv/bin:/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin && cd /absolute/path/to/Big-Data-Technologies-Project && ./.venv/bin/python src/pipeline/daily_pipeline.py >> logs/daily_pipeline.log 2>&1
```

Cron only runs while the computer is awake.

---

## Measurable goals

The platform exposes its own KPIs so we can argue the system actually
works, not just runs.

| Goal | Target | Where it surfaces |
|---|---|---|
| Pipeline runtime (12-year window) | < 25 min | `daily_pipeline.py` log summary |
| % of CVEs with non-null CVSS | > 95% | `data_quality/` |
| % of CVEs in master with EPSS | > 90% | `data_quality/` |
| KEV coverage at capacity 50/day | > 80% | `strategy_comparison/` |
| EPSS-expected exploits prevented (vs. random baseline) | > 10× | `strategy_comparison/` |
| Cluster silhouette (final K) | > 0.10 | `clustering_metrics/` |
| Top-keywords per cluster are interpretable | qualitative | `cluster_topics/` + Streamlit |

---

## Limitations and future work

- **No CPE for ~25% of recent CVEs.** NVD prioritizes KEV-listed CVEs
  for full enrichment as of April 2026; the rest may be missing CPE
  matches. Our `primary_vendor`/`primary_product` columns fall back to
  KEV's own vendor/product when CPE is absent, but the patch plan loses
  granularity for unenriched CVEs.
- **No package-ecosystem coverage.** OSV.dev (npm, PyPI, Cargo, Go,
  Maven…) would let the patch plan target dependency upgrades by
  ecosystem. Out of scope for v1.
- **No streaming layer.** All sources are batch-published. If the
  organization wants to react to new KEV entries within minutes, a
  Kafka topic for KEV deltas would be the natural addition.
- **Single-node Spark only.** Tuned for 8 GB RAM laptops; horizontal
  scale would require swapping `local[*]` for a real cluster and
  adjusting `spark.executor.memory`.
- **No authentication on the Streamlit app.** Single-user demo only.
- **Synthetic capacity-simulator arrivals.** Real arrivals would come
  from the daily NVD `recent` feed; we approximate with a configurable
  `--arrival-rate` parameter for reproducibility.

---

## Team

| Person | Slice | Files owned |
|---|---|---|
| **A** | Infrastructure, ingestion, master | `src/config.py`, `src/utils/http.py`, `src/ingestion/*`, `src/processing/join_master.py`, `src/pipeline/daily_pipeline.py`, `requirements.txt`, `.gitignore`, `README.md` |
| **B** | Data quality, scoring, clustering | `src/processing/data_quality.py`, `src/scoring/priority_scoring.py`, `src/scoring/cluster_aware_scoring.py`, `src/clustering/clustering.py` |
| **C** | Simulation, remediation, app | `src/optimization/capacity_simulation.py`, `src/optimization/remediation_actions.py`, `src/utils/duckdb_helpers.py`, `app/streamlit_app.py` |

Each owner writes the tests for their own files. See
[`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) for the file-by-file
contract and the prompt template each teammate can use with Claude.

---

## License & data attribution

Code: free for academic use.
NVD: U.S. government work, public domain.
CISA KEV: U.S. government work, public domain.
EPSS: FIRST.org, free for any use with attribution.
