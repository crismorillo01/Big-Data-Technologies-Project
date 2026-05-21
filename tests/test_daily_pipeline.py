"""Tests for the daily pipeline step builder."""

from src.pipeline.daily_pipeline import build_steps


def test_daily_pipeline_uses_nvd_modified_by_default():
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
    assert "2025" in steps[0].args
    assert steps[1].name == "ingest_nvd_2026"
    assert "2026" in steps[1].args


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
    assert steps[1].name == "ingest_nvd_2026"
