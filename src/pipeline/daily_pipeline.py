"""Daily batch pipeline for vulnerability intelligence.

This script orchestrates the full vulnerability intelligence pipeline:
ingestion, dataset joining, priority scoring, clustering, and capacity
simulation. It is intended to be executed as a scheduled batch job.
"""

import subprocess
import sys
from datetime import datetime


def run_step(step_name: str, command: list[str]) -> None:
    """Run one pipeline step and stop the pipeline if it fails."""
    print(f"\n=== Running step: {step_name} ===")
    result = subprocess.run(command)

    if result.returncode != 0:
        print(f"Step failed: {step_name}")
        sys.exit(result.returncode)

    print(f"Step completed: {step_name}")


def main():
    """Run the full daily batch pipeline."""
    execution_date = datetime.today().strftime("%Y-%m-%d")
    print(f"Starting daily vulnerability pipeline: {execution_date}")

    spark_base_cmd = [
        "spark-submit",
        "--driver-memory", "6g"
    ]

    run_step(
        "NVD ingestion",
        spark_base_cmd + ["src/ingestion/ingest_nvd.py"]
    )

    run_step(
        "KEV ingestion",
        spark_base_cmd + ["src/ingestion/ingest_kev.py"]
    )

    run_step(
        "EPSS ingestion",
        spark_base_cmd + ["src/ingestion/ingest_epss.py"]
    )

    run_step(
        "Build master dataset",
        spark_base_cmd + ["src/processing/join_master.py"]
    )

    run_step(
        "Priority scoring",
        spark_base_cmd + ["src/scoring/priority_scoring.py"]
    )

    run_step(
        "Clustering",
        spark_base_cmd + [
            "src/clustering/clustering.py",
            "--pca-components", "20",
            "--k-values", "4", "6", "8", "10", "12"
        ]
    )

    run_step(
        "Capacity simulation",
        spark_base_cmd + [
            "src/optimization/capacity_simulation.py",
            "--daily-capacity", "50"
        ]
    )

    print(f"\nPipeline completed successfully: {execution_date}")


if __name__ == "__main__":
    main()
