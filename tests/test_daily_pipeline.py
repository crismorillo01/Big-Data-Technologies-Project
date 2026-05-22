"""Tests for the daily pipeline step builder."""

from src.config import SILVER_NVD_DIR, all_data_directories
from src.pipeline.daily_pipeline import (
    DELTA_SPARK_PACKAGE,
    build_spark_submit_command,
    build_steps,
    has_existing_nvd_silver,
)


def test_daily_pipeline_uses_delta_modified_by_default():
    steps = build_steps(
        nvd_years=[2025, 2026],
        daily_capacity=50,
        simulation_days=30,
        driver_memory="3g",
        snapshot_date="2026-05-21",
        has_nvd_base=True,
    )

    assert steps[0].name == "ingest_nvd_modified"
    assert steps[0].script == "src/ingestion/ingest_nvd_modified.py"
    assert "--snapshot-date" in steps[0].args
    assert "--min-year" in steps[0].args
    assert "2025" in steps[0].args
    assert "--nvd-storage" in steps[0].args
    assert "delta" in steps[0].args


def test_daily_pipeline_can_route_modified_ingestion_to_legacy_parquet():
    steps = build_steps(
        nvd_years=[2025, 2026],
        daily_capacity=50,
        simulation_days=30,
        driver_memory="3g",
        snapshot_date="2026-05-21",
        has_nvd_base=True,
        nvd_storage="parquet",
    )

    assert steps[0].name == "ingest_nvd_modified"
    assert "--nvd-storage" in steps[0].args
    assert "parquet" in steps[0].args


def test_delta_step_adds_delta_package_before_script_path():
    steps = build_steps(
        nvd_years=[2025, 2026],
        daily_capacity=50,
        simulation_days=30,
        driver_memory="3g",
        snapshot_date="2026-05-21",
        has_nvd_base=True,
        nvd_storage="delta",
    )

    cmd = build_spark_submit_command(steps[0], "spark-submit")

    assert "--packages" in cmd
    assert DELTA_SPARK_PACKAGE in cmd
    assert cmd.index("--packages") < cmd.index(str(steps[0].script_path))


def test_join_master_receives_default_delta_storage():
    steps = build_steps(
        nvd_years=[2025, 2026],
        daily_capacity=50,
        simulation_days=30,
        driver_memory="3g",
        snapshot_date="2026-05-21",
        has_nvd_base=True,
    )

    join_step = next(step for step in steps if step.name == "join_master")
    cmd = build_spark_submit_command(join_step, "spark-submit")

    assert "--nvd-storage" in join_step.args
    assert "delta" in join_step.args
    assert "--packages" in cmd
    assert DELTA_SPARK_PACKAGE in cmd


def test_daily_pipeline_refreshes_kev_catalog():
    steps = build_steps(
        nvd_years=[2025, 2026],
        daily_capacity=50,
        simulation_days=30,
        driver_memory="3g",
        snapshot_date="2026-05-21",
        has_nvd_base=True,
    )

    kev_step = next(step for step in steps if step.name == "ingest_kev")

    assert "--force-download" in kev_step.args


def test_daily_pipeline_can_force_full_nvd_refresh():
    steps = build_steps(
        nvd_years=[2025, 2026],
        daily_capacity=50,
        simulation_days=30,
        driver_memory="3g",
        snapshot_date="2026-05-21",
        full_nvd_refresh=True,
        has_nvd_base=True,
    )

    assert steps[0].name == "ingest_nvd_2025"
    assert steps[0].script == "src/ingestion/ingest_nvd.py"
    assert "--force-download" in steps[0].args
    assert "--nvd-storage" in steps[0].args
    assert "delta" in steps[0].args
    assert "--replace-delta-table" in steps[0].args
    assert "--min-year" in steps[0].args
    assert "2025" in steps[0].args
    assert "--skip-parquet-export" not in steps[0].args
    assert steps[1].name == "ingest_nvd_2026"
    assert "2026" in steps[1].args
    assert "--skip-parquet-export" not in steps[1].args


def test_full_nvd_refresh_can_use_legacy_parquet():
    steps = build_steps(
        nvd_years=[2025, 2026],
        daily_capacity=50,
        simulation_days=30,
        driver_memory="3g",
        snapshot_date="2026-05-21",
        full_nvd_refresh=True,
        has_nvd_base=True,
        nvd_storage="parquet",
    )

    first, last = steps[0], steps[1]

    assert first.name == "ingest_nvd_2025"
    assert "--nvd-storage" in first.args
    assert "parquet" in first.args
    assert "--replace-delta-table" not in first.args
    assert "--skip-parquet-export" not in first.args

    assert last.name == "ingest_nvd_2026"
    assert "--nvd-storage" in last.args
    assert "parquet" in last.args
    assert "--replace-delta-table" not in last.args
    assert "--skip-parquet-export" not in last.args

    join_step = next(step for step in steps if step.name == "join_master")
    cmd = build_spark_submit_command(join_step, "spark-submit")

    assert "--nvd-storage" in join_step.args
    assert "parquet" in join_step.args
    assert "--packages" not in cmd


def test_daily_pipeline_uses_full_nvd_refresh_when_base_is_missing():
    steps = build_steps(
        nvd_years=[2025, 2026],
        daily_capacity=50,
        simulation_days=30,
        driver_memory="3g",
        snapshot_date="2026-05-21",
        has_nvd_base=False,
    )

    assert steps[0].name == "ingest_nvd_2025"
    assert steps[0].script == "src/ingestion/ingest_nvd.py"
    assert "--force-download" in steps[0].args
    assert "delta" in steps[0].args
    assert steps[1].name == "ingest_nvd_2026"


def test_delta_base_detection_uses_delta_log(tmp_path):
    parquet_dir = tmp_path / "nvd"
    delta_dir = tmp_path / "nvd_delta"
    (delta_dir / "_delta_log").mkdir(parents=True)

    assert has_existing_nvd_silver(
        nvd_storage="delta",
        silver_nvd_dir=parquet_dir,
        silver_nvd_delta_dir=delta_dir,
    )
    assert not has_existing_nvd_silver(
        nvd_storage="parquet",
        silver_nvd_dir=parquet_dir,
        silver_nvd_delta_dir=delta_dir,
    )


def test_legacy_nvd_parquet_dir_is_not_created_by_global_directory_setup():
    assert SILVER_NVD_DIR not in all_data_directories()
