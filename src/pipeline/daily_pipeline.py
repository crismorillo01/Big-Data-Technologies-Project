"""Daily batch orchestrator for the vulnerability intelligence pipeline.

This script chains every Spark job into one deterministic, end-to-end run.
It is the simplest possible orchestrator — a sequence of ``spark-submit``
subprocesses — kept here as the always-working fallback to the optional
Airflow DAG.

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
    configure_logging,
)


logger = logging.getLogger(__name__)


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


def build_steps(
    nvd_years: list[int],
    daily_capacity: int,
    simulation_days: int,
    driver_memory: str,
) -> list[Step]:
    """Build the ordered list of pipeline steps."""
    common_driver = ("--driver-memory", driver_memory)
    return [
        Step(
            name="ingest_nvd",
            script="src/ingestion/ingest_nvd.py",
            args=common_driver + ("--years", *map(str, nvd_years)),
            owner="A",
        ),
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
            args=common_driver,
            owner="A",
        ),
        Step(
            name="data_quality",
            script="src/processing/data_quality.py",
            args=common_driver,
            owner="B",
        ),
        Step(
            name="priority_scoring",
            script="src/scoring/priority_scoring.py",
            args=common_driver,
            owner="B",
        ),
        Step(
            name="clustering",
            script="src/clustering/clustering.py",
            args=common_driver,
            owner="B",
        ),
        Step(
            name="cluster_aware_scoring",
            script="src/scoring/cluster_aware_scoring.py",
            args=common_driver,
            owner="B",
        ),
        Step(
            name="capacity_simulation",
            script="src/optimization/capacity_simulation.py",
            args=common_driver + (
                "--daily-capacity", str(daily_capacity),
                "--simulation-days", str(simulation_days),
            ),
            owner="C",
        ),
        Step(
            name="remediation_actions",
            script="src/optimization/remediation_actions.py",
            args=common_driver,
            owner="C",
        ),
    ]


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

def run_step(step: Step) -> bool:
    """Run one step. Returns True on success, False on script-not-found."""
    if not step.script_path.exists():
        logger.warning(
            "[%s] script not found at %s (owner: %s) — SKIPPED",
            step.name, step.script, step.owner or "?",
        )
        return False

    logger.info("=== Step: %s (owner %s) ===", step.name, step.owner or "?")
    cmd = ["spark-submit", str(step.script_path), *step.args]
    logger.info("  command: %s", " ".join(cmd))

    result = subprocess.run(cmd, cwd=str(_PROJECT_ROOT))
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
    )

    logger.info("Vulnerability intelligence pipeline starting")
    logger.info("  years=%s", args.years)
    logger.info("  daily_capacity=%d  simulation_days=%d", args.daily_capacity, args.simulation_days)
    logger.info("  driver_memory=%s", args.driver_memory)

    run_pipeline(steps)


if __name__ == "__main__":
    main()
