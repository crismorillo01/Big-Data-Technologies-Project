# Vulnerability Intelligence Platform

A Big Data pipeline that ingests public vulnerability disclosures (NVD,
CISA KEV, EPSS), enriches them with cluster-aware risk signals, and
produces a ranked patch plan for security teams operating under limited
remediation capacity.

---

## Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│ Runtime / Packaging                                                │
│   Dockerfile                                                       │
│   docker-compose.yml                                               │
│   app service → Streamlit on port 8501                             │
│   pipeline service → daily_pipeline.py with forwarded CLI args     │
└────────────────────────────────────────────────────────────────────┘
     │
     ▼
┌────────────────────────────────────────────────────────────────────┐
│ Orchestration                                                      │
│   src/pipeline/daily_pipeline.py    (CLI, Docker, or cron entry)   │
└────────────────────────────────────────────────────────────────────┘
     │
     ▼
┌────────────────────────────────────────────────────────────────────┐
│ Ingestion                                                          │
│   ingest_nvd.py | ingest_nvd_modified.py | ingest_kev.py |         │
│   ingest_epss.py                                                   │
└────────────────────────────────────────────────────────────────────┘
     │
     ▼
┌────────────────────────────────────────────────────────────────────┐
│ data/raw/                                                          │
│   NVD JSON / modified JSON, KEV CSV, EPSS CSV snapshots            │
└────────────────────────────────────────────────────────────────────┘
     │
     ▼
┌────────────────────────────────────────────────────────────────────┐
│ data/silver/                                                       │
│   nvd/year=YYYY/ or nvd_delta/ (+ nvd_updates/ lineage)            │
│   kev/                                                             │
│   epss/score_date=YYYY-MM-DD/                                      │
└────────────────────────────────────────────────────────────────────┘
     │
     ▼
join_master  ───────────►  data_quality (metrics → gold)
     │
     ▼
┌────────────────────────────────────────────────────────────────────┐
│ data/gold/master_vulnerabilities/                                  │
│   published_year=YYYY/snapshot_date=YYYY-MM-DD/                    │
└────────────────────────────────────────────────────────────────────┘
     │
     ▼
priority_scoring         (CVSS + EPSS percentile + KEV + recency)
     │
     ▼
clustering               (TF-IDF + CWE + vendor/product + numeric)
     │
     ▼
cluster_aware_scoring    (cluster density + cluster EPSS max)
     │
     ▼
capacity_simulation      (5 strategies, multi-day backlog simulation)
     │
     ▼
remediation_actions      (ranked patch plan grouped by (vendor, product))
     │
     ▼
┌────────────────────────────────────────────────────────────────────┐
│ Serving layer                                                      │
│   DuckDB queries gold Parquet directly.                            │
│   Streamlit app exposes the results interactively.                 │
└────────────────────────────────────────────────────────────────────┘
```

The data follows a **medallion architecture**: raw stores immutable
downloads, silver stores typed partitioned snapshots, and gold stores the
analytics-ready tables. The NVD silver layer supports both the current
Delta-backed flow and a Parquet fallback, while EPSS keeps one partition
per `score_date`. Gold tables are partitioned by `snapshot_date`, so
historical runs are preserved and re-running the pipeline only overwrites
the current day's partition.

The project is built as a batch pipeline because its core goal is to model
the daily remediation capacity of an organization: how many vulnerabilities
can realistically be resolved in one day. That makes a batch run a better
fit than streaming, especially because the upstream datasets are updated at
snapshot or feed intervals rather than continuously. NVD is the most
frequent source, but even though its feeds refresh every two hours, they do
not always contain new changes, and the number of new daily entries is small
compared with the full catalog.

---

## Data sources

| Source | Format | Update frequency | Volume (12y window) | Role |
|---|---|---|---|---|
| **NVD** (NIST National Vulnerability Database) | gzipped JSON, yearly feeds | Yearly feeds: daily / `recent` and `modified` feeds: every 2 h | ~250–300 K CVEs | Authoritative CVE catalog with CVSS, CWE, CPE, references |
| **CISA KEV** (Known Exploited Vulnerabilities) | CSV, single snapshot | Weekdays, US business hours, ad-hoc (avg ~1/day) | ~1.5 K CVEs cumulative | Ground-truth flag for actively exploited CVEs |
| **EPSS** (Exploit Prediction Scoring System) | gzipped CSV, daily snapshot | Once per day | ~250 K rows per snapshot | Probabilistic exploit-likelihood score |

All three are public, free, and stable.

---

## Repository layout

```
.
├── README.md                        ← this file
├── requirements.txt                 ← Python package dependencies
├── Dockerfile                       ← image definition for app + pipeline
├── docker-compose.yml               ← local app/pipeline service setup
├── docker-entrypoint.sh             ← container command router
├── .dockerignore                    ← excludes data, caches, and build junk
├── .gitignore                       ← excludes generated files and local-only artifacts
├── team_contributions/              ← individual team member contribution notes
├── src/
│   ├── config.py                    ← paths, defaults, Spark session factory
│   ├── ingestion/
│   │   ├── ingest_nvd.py            ← full NVD yearly ingest
│   │   ├── ingest_nvd_modified.py   ← modified-feed incremental upsert
│   │   ├── ingest_kev.py            ← KEV snapshot ingest
│   │   └── ingest_epss.py           ← daily EPSS snapshots
│   ├── processing/
│   │   ├── join_master.py           ← master assembly
│   │   └── data_quality.py          ← snapshot metrics
│   ├── scoring/
│   │   ├── priority_scoring.py      ← base score
│   │   └── cluster_aware_scoring.py ← cluster-adjusted score
│   ├── clustering/
│   │   └── clustering.py            ← vulnerability clustering
│   ├── optimization/
│   │   ├── capacity_simulation.py   ← strategy simulation
│   │   └── remediation_actions.py   ← ranked patch plan
│   ├── pipeline/
│   │   └── daily_pipeline.py        ← end-to-end orchestrator
│   └── utils/
│       ├── http.py                  ← download helpers + retries
│       └── duckdb_helpers.py        ← serving-layer SQL helpers
├── app/
│   └── streamlit_app.py             ← Streamlit UI
├── tests/
│   └── test_*.py                    ← full pytest suite
└── data/                            ← gitignored; created on first run
    ├── raw/
    ├── silver/
    └── gold/
```

---

## Running the pipeline

### Clone the repository

```bash
git clone <repo>
cd Big-Data-Technologies-Project
```

### Prerequisites

- Python 3.10 or 3.11
- Java 11 or 17 (PySpark requirement; `brew install openjdk@17` on macOS)
- ~8 GB RAM (the Spark session is tuned for this; see `src/config.py`)
- ≥8 CPU Cores
- Docker Desktop or Docker Engine with Docker Compose v2, if you want to
  use the containerized workflow

### Running with Docker Compose

Docker Compose is the recommended way to run the project locally.
Make sure Docker is running before you launch any of the commands below.
The `pipeline` service runs the pipeline code and the `app` service serves
the Streamlit UI. Both services share the same image and write their
outputs to `./data`.

Recommended commands:

| Situation | Command |
|---|---|
| First run, or after rebuilding the image | `docker compose up --build -d` |
| Start the app after the image is already built | `docker compose up app` |
| Run the pipeline with arguments | `docker compose run --rm pipeline` |

Build and launch in one step:

```bash
docker compose up --build -d
```

Start the app again after the image is already built:

```bash
docker compose up app
```

Run the pipeline on demand:

```bash
docker compose run --rm pipeline
```

The pipeline also accepts these arguments:

| Argument | Default | Example | What it does |
|---|---|---|---|
| `--years` | `2015 2016 2017 2018 2019 2020 2021 2022 2023 2024 2025 2026` | `docker compose run --rm pipeline --years 2024 2025 2026` | Limits the NVD ingestion window to the listed years. Useful for smaller, faster runs. |
| `--daily-capacity` | `50` | `docker compose run --rm pipeline --daily-capacity 30` | Sets how many vulnerabilities the capacity simulator assumes can be remediated per day. |
| `--simulation-days` | `30` | `docker compose run --rm pipeline --simulation-days 60` | Controls how many days the multi-day simulation should cover. |
| `--driver-memory` | `3g` | `docker compose run --rm pipeline --driver-memory 2g` | Sets the Spark driver heap passed to every step. Lower it on machines with limited RAM. |
| `--snapshot-date` | `today UTC` | `docker compose run --rm pipeline --snapshot-date 2026-05-10` | Forces the gold-layer snapshot date used by the downstream jobs. |
| `--full-nvd-refresh` | `off` | `docker compose run --rm pipeline --full-nvd-refresh` | Re-downloads every yearly NVD feed instead of using the incremental modified feed. |
| `--nvd-storage` | `delta` | `docker compose run --rm pipeline --nvd-storage parquet` | Chooses the storage format for NVD silver output. Use `delta` for the current default flow or `parquet` for legacy mode. |

The app is available at `http://localhost:8501`.

To stop Docker Compose:

- If you launched it in the foreground, press `Ctrl+C`.
- If you launched it in detached mode, run `docker compose down`.

### Local CLI setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### One command, end to end

```bash
python src/pipeline/daily_pipeline.py
```

That runs every step in order. The pipeline also accepts the same
arguments as Docker Compose, so you can pass `--driver-memory`,
`--snapshot-date`, `--full-nvd-refresh`, `--nvd-storage`, and the rest
directly to `python src/pipeline/daily_pipeline.py`.

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

Opens at `http://localhost:8501`.

### Daily scheduling with cron

On macOS/Linux, cron can run the same pipeline every day. Create the
logs directory first:

```bash
mkdir -p logs
```

Then edit the crontab:

```bash
EDITOR=nano crontab -e
```

You can schedule the pipeline in two ways:

- **Docker / Docker Compose**

  This option uses the image defined in `Dockerfile` and the service
  configuration in `docker-compose.yml`, so it does not need the local
  `.venv` or `JAVA_HOME` setup. Docker Desktop or the Docker daemon must
  be running when the job fires.

  Replace the placeholder path with the absolute path on the machine that
  will run the job:

  ```cron
  0 20 * * * export PATH=/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin && cd /absolute/path/to/Big-Data-Technologies-Project && docker compose run --rm pipeline >> /absolute/path/to/Big-Data-Technologies-Project/logs/daily_pipeline.log 2>&1
  ```

- **Local Python environment**

  Replace the placeholder paths with the absolute paths on the machine
  that will run the job:

  ```cron
  0 20 * * * export JAVA_HOME=/absolute/path/to/java && export PATH=/absolute/path/to/java/bin:/absolute/path/to/Big-Data-Technologies-Project/.venv/bin:/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin && cd /absolute/path/to/Big-Data-Technologies-Project && ./.venv/bin/python src/pipeline/daily_pipeline.py >> logs/daily_pipeline.log 2>&1
  ```

Cron only runs while the computer is awake.

## Team

| Member | Main slice | Current files |
|---|---|---|
| Cristina Morillo | Infrastructure, ingestion, master, pipeline, Docker | `src/config.py`, `src/utils/http.py`, `src/ingestion/*`, `src/processing/join_master.py`, `src/pipeline/daily_pipeline.py`, `Dockerfile`, `docker-compose.yml`, `docker-entrypoint.sh` |
| Francesco Leoni | Data quality, scoring, clustering | `src/processing/data_quality.py`, `src/scoring/priority_scoring.py`, `src/scoring/cluster_aware_scoring.py`, `src/clustering/clustering.py` |
| Vo Thuy Trang | Simulation, remediation, serving app | `src/optimization/capacity_simulation.py`, `src/optimization/remediation_actions.py`, `src/utils/duckdb_helpers.py`, `app/streamlit_app.py` |

Each contributor owns the tests for their slice.

---

## License & data attribution

Code: free for academic use.
NVD: U.S. government work, public domain.
CISA KEV: U.S. government work, public domain.
EPSS: FIRST.org, free for any use with attribution.
