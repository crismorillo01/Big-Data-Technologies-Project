"""Central configuration for the vulnerability intelligence pipeline.

Single source of truth for filesystem paths, pipeline defaults and the
Spark session factory. No other module under ``src/`` should hardcode a
data path or duplicate the Spark configuration.

Conventions
-----------
- Every path is exposed as a ``pathlib.Path`` constant. Convert to ``str``
  with ``str(path)`` before passing to PySpark APIs that require strings.
- The Spark session is tuned for a single-node 8 GB RAM machine running
  in ``local[*]`` mode. Executor memory is intentionally not set because
  in local mode the executor lives inside the driver process.
- Snapshot dates use UTC to avoid surprises when the pipeline runs near
  midnight in different time zones.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

from pyspark.sql import SparkSession


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOG_FORMAT = "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def configure_logging(level: int = logging.INFO) -> None:
    """Configure root logging once per process. Idempotent.

    Pipeline scripts call this in their ``main()`` before any other work so
    we get consistent timestamps and module names in every log line.
    """
    root = logging.getLogger()
    if root.handlers:
        # Already configured (e.g. by another module or pytest). Just adjust the level.
        root.setLevel(level)
        return
    logging.basicConfig(level=level, format=LOG_FORMAT, datefmt=LOG_DATE_FORMAT)


# ---------------------------------------------------------------------------
# Filesystem layout
# ---------------------------------------------------------------------------

# Repository root: this file lives at <root>/src/config.py, so .parent.parent
# resolves to <root>. Keeping this as the single anchor avoids string-based paths.
PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
DATA_DIR: Path = PROJECT_ROOT / "data"

# ---- Raw layer (untouched downloads) -------------------------------------
RAW_DIR: Path = DATA_DIR / "raw"
RAW_NVD_DIR: Path = RAW_DIR / "nvd"                         # nvdcve-2.0-YYYY.json.gz
RAW_NVD_JSON_DIR: Path = RAW_DIR / "nvd_json"               # nvdcve-2.0-YYYY.json
RAW_KEV_DIR: Path = RAW_DIR / "kev"
RAW_KEV_FILE: Path = RAW_KEV_DIR / "known_exploited_vulnerabilities.csv"
RAW_EPSS_DIR: Path = RAW_DIR / "epss"                       # epss_scores-YYYY-MM-DD.csv[.gz]

# ---- Silver layer (clean, typed, partitioned Parquet) --------------------
SILVER_DIR: Path = DATA_DIR / "silver"
SILVER_NVD_DIR: Path = SILVER_DIR / "nvd"                   # partition: year=YYYY
SILVER_KEV_DIR: Path = SILVER_DIR / "kev"
SILVER_EPSS_DIR: Path = SILVER_DIR / "epss"                 # partition: score_date=YYYY-MM-DD

# ---- Gold layer (analytics-ready) ----------------------------------------
GOLD_DIR: Path = DATA_DIR / "gold"
GOLD_MASTER_DIR: Path = GOLD_DIR / "master_vulnerabilities"  # part: published_year, snapshot_date
GOLD_DATA_QUALITY_DIR: Path = GOLD_DIR / "data_quality"      # part: snapshot_date
GOLD_VULN_SCORES_DIR: Path = GOLD_DIR / "vulnerability_scores"          # base score
GOLD_VULN_SCORES_FINAL_DIR: Path = GOLD_DIR / "vulnerability_scores_final"  # cluster-aware
GOLD_VULN_CLUSTERED_DIR: Path = GOLD_DIR / "vulnerabilities_clustered"
GOLD_CLUSTERING_METRICS_DIR: Path = GOLD_DIR / "clustering_metrics"
GOLD_CLUSTER_TOPICS_DIR: Path = GOLD_DIR / "cluster_topics"
GOLD_CLUSTER_RISK_SUMMARY_DIR: Path = GOLD_DIR / "cluster_risk_summary"
GOLD_STRATEGY_COMPARISON_DIR: Path = GOLD_DIR / "strategy_comparison"
GOLD_REMEDIATION_RECOMMENDATIONS_DIR: Path = GOLD_DIR / "remediation_recommendations"
GOLD_REMEDIATION_ACTIONS_DIR: Path = GOLD_DIR / "remediation_actions"
GOLD_SIMULATION_TIMESERIES_DIR: Path = GOLD_DIR / "simulation_timeseries"


def all_data_directories() -> tuple[Path, ...]:
    """Return every data directory the pipeline writes to."""
    return (
        RAW_NVD_DIR, RAW_NVD_JSON_DIR, RAW_KEV_DIR, RAW_EPSS_DIR,
        SILVER_NVD_DIR, SILVER_KEV_DIR, SILVER_EPSS_DIR,
        GOLD_DIR,
    )


def ensure_data_directories() -> None:
    """Create every data directory if it does not exist yet. Safe to call repeatedly."""
    for directory in all_data_directories():
        directory.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Pipeline defaults
# ---------------------------------------------------------------------------

# 12-year window (2015 ... 2026 inclusive). Earlier years are sparse and
# add little to the volume argument. Override via CLI if needed.
DEFAULT_NVD_YEARS: list[int] = list(range(2015, 2027))

# Capacity simulator
DEFAULT_DAILY_CAPACITY: int = 50      # patches the team can ship per day
DEFAULT_SIMULATION_DAYS: int = 30     # horizon of the multi-day simulation
DEFAULT_ARRIVAL_RATE: int = 50        # synthetic CVE arrivals per day

# Base scoring weights (must sum to 1.0 for cvss + epss + kev; recency is additive)
DEFAULT_CVSS_WEIGHT: float = 0.4
DEFAULT_EPSS_WEIGHT: float = 0.4
DEFAULT_KEV_WEIGHT: float = 0.2
DEFAULT_RECENCY_WEIGHT: float = 0.0   # off by default; surface as flag for sensitivity
# KEV override: any CVE in KEV gets at least this priority score, regardless of weights
DEFAULT_KEV_OVERRIDE_FLOOR: float = 0.9

# Cluster-aware scoring coefficients (priority_final = priority * (1 + alpha * kev_density)
# + beta * cluster_epss_max, then clipped to [0, 1.5])
DEFAULT_CLUSTER_KEV_ALPHA: float = 0.5
DEFAULT_CLUSTER_EPSS_BETA: float = 0.1
PRIORITY_FINAL_MAX: float = 1.5

# Priority level thresholds (used by both base and final scoring)
PRIORITY_LEVEL_THRESHOLDS: dict[str, float] = {
    "Critical": 0.8,
    "High": 0.6,
    "Medium": 0.4,
    # anything below 0.4 is "Low"
}


# ---------------------------------------------------------------------------
# Spark session
# ---------------------------------------------------------------------------

def create_spark_session(
    app_name: str,
    driver_memory: str = "3g",
    shuffle_partitions: int = 8,
    extra_config: dict[str, str] | None = None,
) -> SparkSession:
    """Build a Spark session tuned for a single-node 8 GB RAM laptop.

    Parameters
    ----------
    app_name :
        Visible name of the Spark application (also used as log prefix).
    driver_memory :
        JVM heap given to the Spark driver. In ``local[*]`` mode the driver
        IS the executor, so ``executor.memory`` has no effect. Default
        ``"3g"`` leaves ~5 GB for the OS, browser and IDE on an 8 GB box.
        Lower to ``"2g"`` if you see OS pressure; raise to ``"4g"`` for
        heavy clustering runs after closing other apps.
    shuffle_partitions :
        Default 8 (≈ 2× physical cores on a typical laptop). The Spark
        default of 200 is wildly inappropriate for single-node and produces
        massive task overhead.
    extra_config :
        Optional ad-hoc Spark configs that override defaults set here.

    Notes
    -----
    Adaptive Query Execution and partition coalescing are on by default —
    this gives Spark room to merge tiny shuffle partitions back together
    when the data turns out to be small. Kryo is the serializer because it
    is 2-3× faster than the Java default for the kinds of joins this
    pipeline does.
    """
    builder = (
        SparkSession.builder
        .appName(app_name)
        .master("local[*]")
        .config("spark.driver.memory", driver_memory)
        .config("spark.driver.maxResultSize", "1g")
        .config("spark.sql.shuffle.partitions", str(shuffle_partitions))
        .config("spark.sql.adaptive.enabled", "true")
        .config("spark.sql.adaptive.coalescePartitions.enabled", "true")
        .config("spark.serializer", "org.apache.spark.serializer.KryoSerializer")
        .config("spark.memory.fraction", "0.6")
        # Partitioned writes: re-running a snapshot replaces only that partition
        # instead of wiping the whole dataset.
        .config("spark.sql.sources.partitionOverwriteMode", "dynamic")
        # Suppress noisy "WARN NativeCodeLoader: Unable to load native-hadoop"
        # without losing real warnings.
        .config("spark.hadoop.io.native.lib.available", "false")
    )

    if extra_config:
        for key, value in extra_config.items():
            builder = builder.config(key, value)

    spark = builder.getOrCreate()
    spark.sparkContext.setLogLevel("WARN")
    return spark


# ---------------------------------------------------------------------------
# Date helpers
# ---------------------------------------------------------------------------

def get_snapshot_date() -> str:
    """Return today's UTC date as ``YYYY-MM-DD``.

    Used as the partition key for snapshot-style tables (master,
    vulnerability_scores, simulation_timeseries, etc.). UTC is intentional:
    re-running the pipeline twice on the same calendar day in different
    time zones must hit the same partition.
    """
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
