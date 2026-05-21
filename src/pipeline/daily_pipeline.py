"""Daily batch orchestrator for the vulnerability intelligence pipeline.

This script chains every Spark job into one deterministic, end-to-end run.
It is the simplest possible orchestrator — a sequence of ``spark-submit``
subprocesses — and is the entry point for manual runs or the daily cron
schedule.

Step order
----------
1.  ingest_nvd                (Person A)
2.  ingest_kev                (Person A)
3.  ingest_epss               (Person A)
4.  join_master               (Person A)
5.  data_quality              (Person B)
6.  priority_scoring          (Person B)
7.  clustering                (Person B)
8.  cluster_aware_scoring     (Person B)
9.  capacity_simulation       (Person C)
10. remediation_actions       (Person C)

Steps whose script does not yet exist are skipped with a WARNING. This
lets us run the pipeline incrementally during the team's parallel work
without any step having to be commented out by hand. Once the full team
has delivered, every step exists and nothing is skipped.
"""

from __future__ import annotations

import argparse
import logging
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

# Allow plain-script execution: `python src/pipeline/daily_pipeline.py`
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.config import (  # noqa: E402
    DEFAULT_DAILY_CAPACITY,
    DEFAULT_NVD_YEARS,
    DEFAULT_SIMULATION_DAYS,
    SILVER_NVD_DELTA_DIR,
    SILVER_NVD_DIR,
    configure_logging,
    get_snapshot_date,
)


logger = logging.getLogger(__name__)

DELTA_SPARK_PACKAGE = "io.delta:delta-spark_2.12:3.1.0"
DELTA_SPARK_SUBMIT_ARGS = (
    "--packages", DELTA_SPARK_PACKAGE,
    "--conf", "spark.sql.extensions=io.delta.sql.DeltaSparkSessionExtension",
    "--conf", "spark.sql.catalog.spark_catalog=org.apache.spark.sql.delta.catalog.DeltaCatalog",
)


# ---------------------------------------------------------------------------
# Step model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Step:
    """One pipeline step. ``script`` is the path relative to the project root."""
    name: str
    script: str
    args: tuple[str, ...] = ()
    owner: str = ""

    @property
    def script_path(self) -> Path:
        return _PROJECT_ROOT / self.script


def has_existing_nvd_silver(
    nvd_storage: str = "delta",
    silver_nvd_dir: Path = SILVER_NVD_DIR,
    silver_nvd_delta_dir: Path = SILVER_NVD_DELTA_DIR,
) -> bool:
    """Return True when a usable NVD silver base exists for the selected storage."""
    parquet_exists = silver_nvd_dir.exists() and any(silver_nvd_dir.rglob("*.parquet"))
    delta_exists = (silver_nvd_delta_dir / "_delta_log").exists()

    if nvd_storage == "delta":
        # A legacy Parquet base is still usable because the modified job can
        # bootstrap the Delta table from it once.
        return delta_exists or parquet_exists

    return parquet_exists


def build_steps(
    nvd_years: list[int],
    daily_capacity: int,
    simulation_days: int,
    driver_memory: str,
    snapshot_date: str,
    full_nvd_refresh: bool = False,
    has_nvd_base: bool | None = None,
    nvd_storage: str = "delta",
) -> list[Step]:
    """Build the ordered list of pipeline steps."""
    common_driver = ("--driver-memory", driver_memory)
    common_snapshot = ("--snapshot-date", snapshot_date)
    min_nvd_year = min(nvd_years)
    use_full_nvd_refresh = full_nvd_refresh or not (
        has_existing_nvd_silver(nvd_storage=nvd_storage) if has_nvd_base is None else has_nvd_base
    )
    nvd_steps = (
        [
            Step(
                name=f"ingest_nvd_{year}",
                script="src/ingestion/ingest_nvd.py",
                args=common_driver + (
                    "--force-download",
                    "--years", str(year),
                    "--nvd-storage", nvd_storage,
                    *(("--replace-delta-table",) if nvd_storage == "delta" and index == 0 else ()),
                ),
                owner="A",
            )
            for index, year in enumerate(nvd_years)
        ]
        if use_full_nvd_refresh
        else [
            Step(
                name="ingest_nvd_modified",
                script="src/ingestion/ingest_nvd_modified.py",
                args=common_driver + common_snapshot + (
                    "--min-year", str(min_nvd_year),
                    "--nvd-storage", nvd_storage,
                ),
                owner="A",
            )
        ]
    )
    return [
        *nvd_steps,
        Step(
            name="ingest_kev",
            script="src/ingestion/ingest_kev.py",
            args=common_driver,
            owner="A",
        ),
        Step(
            name="ingest_epss",
            script="src/ingestion/ingest_epss.py",
            args=common_driver,
            owner="A",
        ),
        Step(
            name="join_master",
            script="src/processing/join_master.py",
            args=common_driver + common_snapshot + ("--nvd-storage", nvd_storage),
            owner="A",
        ),
        Step(
            name="data_quality",
            script="src/processing/data_quality.py",
            args=common_driver + common_snapshot,
            owner="B",
        ),
        Step(
            name="priority_scoring",
            script="src/scoring/priority_scoring.py",
            args=common_driver + common_snapshot,
            owner="B",
        ),
        Step(
            name="clustering",
            script="src/clustering/clustering.py",
            args=common_driver + common_snapshot,
            owner="B",
        ),
        Step(
            name="cluster_aware_scoring",
            script="src/scoring/cluster_aware_scoring.py",
            args=common_driver + common_snapshot,
            owner="B",
        ),
        Step(
            name="capacity_simulation",
            script="src/optimization/capacity_simulation.py",
            args=common_driver + (
                *common_snapshot,
                "--daily-capacity", str(daily_capacity),
                "--simulation-days", str(simulation_days),
            ),
            owner="C",
        ),
        Step(
            name="remediation_actions",
            script="src/optimization/remediation_actions.py",
            args=common_driver + common_snapshot,
            owner="C",
        ),
    ]


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

def _find_spark_submit() -> str:
    """Return the path to spark-submit, preferring the active venv.

    On Windows, spark-submit ships as spark-submit.cmd inside the venv's
    Scripts/ directory. subprocess.run cannot find .cmd files via plain
    name lookup, so we resolve the full path here.
    """
    venv_bin = Path(sys.executable).parent
    candidate_names = (
        ("spark-submit.cmd", "spark-submit")
        if os.name == "nt"
        else ("spark-submit", "spark-submit.cmd")
    )

    for name in candidate_names:
        candidate = venv_bin / name
        if candidate.exists():
            return str(candidate)

    for name in candidate_names:
        found = shutil.which(name)
        if found:
            return found

    raise RuntimeError(
        "spark-submit not found. Activate the project venv or add PySpark's "
        "Scripts directory to PATH."
    )


def _step_uses_delta(step: Step) -> bool:
    """Return True when the step requests Delta-backed NVD storage."""
    return "--nvd-storage" in step.args and "delta" in step.args


def build_spark_submit_command(step: Step, spark_submit: str) -> list[str]:
    """Build the spark-submit command for one step."""
    spark_submit_args = DELTA_SPARK_SUBMIT_ARGS if _step_uses_delta(step) else ()
    return [spark_submit, *spark_submit_args, str(step.script_path), *step.args]


def run_step(step: Step) -> bool:
    """Run one step. Returns True on success, False on script-not-found."""
    if not step.script_path.exists():
        logger.warning(
            "[%s] script not found at %s (owner: %s) — SKIPPED",
            step.name, step.script, step.owner or "?",
        )
        return False

    logger.info("=== Step: %s (owner %s) ===", step.name, step.owner or "?")
    spark_submit = _find_spark_submit()
    cmd = build_spark_submit_command(step, spark_submit)
    logger.info("  command: %s", " ".join(cmd))

    # Pass PYSPARK_PYTHON so the JVM spawns workers from the active venv,
    # not the system Python (which on Windows may be the Store stub).
    env = {
        **os.environ,
        "PYSPARK_PYTHON": sys.executable,
        "PYSPARK_DRIVER_PYTHON": sys.executable,
    }
    result = subprocess.run(cmd, cwd=str(_PROJECT_ROOT), env=env)
    if result.returncode != 0:
        logger.error("[%s] FAILED with exit code %d", step.name, result.returncode)
        sys.exit(result.returncode)

    logger.info("[%s] completed", step.name)
    return True


def run_pipeline(steps: list[Step]) -> None:
    """Run every step in order, stopping on the first failure."""
    started = len(steps)
    skipped = 0
    for step in steps:
        ok = run_step(step)
        if not ok:
            skipped += 1

    completed = started - skipped
    logger.info("Pipeline finished: %d/%d steps run, %d skipped (missing script)",
                completed, started, skipped)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Run the full vulnerability intelligence pipeline."
    )
    parser.add_argument(
        "--years",
        nargs="+",
        type=int,
        default=DEFAULT_NVD_YEARS,
        help=f"NVD years. Default: {DEFAULT_NVD_YEARS}",
    )
    parser.add_argument(
        "--daily-capacity",
        type=int,
        default=DEFAULT_DAILY_CAPACITY,
        help=f"Patches per day for the simulator. Default: {DEFAULT_DAILY_CAPACITY}",
    )
    parser.add_argument(
        "--simulation-days",
        type=int,
        default=DEFAULT_SIMULATION_DAYS,
        help=f"Horizon of the multi-day simulation. Default: {DEFAULT_SIMULATION_DAYS}",
    )
    parser.add_argument(
        "--driver-memory",
        default="3g",
        help="Spark driver memory passed to every step. Default: 3g.",
    )
    parser.add_argument(
        "--snapshot-date",
        default=get_snapshot_date(),
        help="Gold-layer snapshot date (YYYY-MM-DD). Default: today UTC.",
    )
    parser.add_argument(
        "--full-nvd-refresh",
        action="store_true",
        help="Re-download every yearly NVD feed instead of using the daily modified feed.",
    )
    parser.add_argument(
        "--nvd-storage",
        choices=["parquet", "delta"],
        default="delta",
        help="Storage engine for NVD silver. Default: delta. Use parquet for legacy Parquet-only mode.",
    )
    return parser.parse_args()


def main() -> None:
    """Entry point. ``python src/pipeline/daily_pipeline.py``."""
    configure_logging()
    args = parse_args()

    steps = build_steps(
        nvd_years=args.years,
        daily_capacity=args.daily_capacity,
        simulation_days=args.simulation_days,
        driver_memory=args.driver_memory,
        snapshot_date=args.snapshot_date,
        full_nvd_refresh=args.full_nvd_refresh,
        nvd_storage=args.nvd_storage,
    )

    logger.info("Vulnerability intelligence pipeline starting")
    logger.info("  years=%s", args.years)
    logger.info("  daily_capacity=%d  simulation_days=%d", args.daily_capacity, args.simulation_days)
    logger.info("  driver_memory=%s", args.driver_memory)
    logger.info("  snapshot_date=%s", args.snapshot_date)
    logger.info("  full_nvd_refresh=%s", args.full_nvd_refresh)
    logger.info("  nvd_storage=%s", args.nvd_storage)
    logger.info("  nvd_silver_base_exists=%s", has_existing_nvd_silver(nvd_storage=args.nvd_storage))

    run_pipeline(steps)


if __name__ == "__main__":
    main()
