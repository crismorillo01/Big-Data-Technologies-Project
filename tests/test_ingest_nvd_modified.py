"""Tests for NVD modified-feed upserts."""

from __future__ import annotations

from datetime import datetime

from src.ingestion.ingest_nvd_modified import upsert_nvd_modified


def test_upsert_nvd_modified_updates_existing_and_inserts_new(spark, tmp_path):
    output_dir = tmp_path / "silver" / "nvd"

    existing = spark.createDataFrame(
        [
            {
                "cve_id": "CVE-2024-0001",
                "published_year": 2024,
                "last_modified": datetime(2024, 1, 1),
                "description": "old description",
            },
            {
                "cve_id": "CVE-2024-0002",
                "published_year": 2024,
                "last_modified": datetime(2024, 1, 2),
                "description": "unchanged",
            },
        ]
    )
    existing.write.mode("overwrite").parquet(str(output_dir / "year=2024"))

    modified = spark.createDataFrame(
        [
            {
                "cve_id": "CVE-2024-0001",
                "published_year": 2024,
                "last_modified": datetime(2024, 2, 1),
                "description": "new description",
            },
            {
                "cve_id": "CVE-2024-0003",
                "published_year": 2024,
                "last_modified": datetime(2024, 2, 2),
                "description": "new cve",
            },
        ]
    )

    stats = upsert_nvd_modified(
        spark,
        modified,
        output_dir=output_dir,
        snapshot_date="2026-05-21",
    )

    rows = {
        row["cve_id"]: row.asDict()
        for row in spark.read.parquet(str(output_dir / "year=2024")).collect()
    }

    assert stats["modified_rows"] == 2
    assert stats["affected_years"] == 1
    assert rows["CVE-2024-0001"]["description"] == "new description"
    assert rows["CVE-2024-0002"]["description"] == "unchanged"
    assert rows["CVE-2024-0003"]["description"] == "new cve"
    assert len(rows) == 3


def test_upsert_nvd_modified_removes_old_copy_from_previous_year_partition(spark, tmp_path):
    output_dir = tmp_path / "silver" / "nvd"

    old_partition = spark.createDataFrame(
        [
            {
                "cve_id": "CVE-2021-0001",
                "published_year": 2021,
                "last_modified": datetime(2021, 1, 1),
                "description": "old misplaced copy",
            }
        ]
    )
    old_partition.write.mode("overwrite").parquet(str(output_dir / "year=2026"))

    modified = spark.createDataFrame(
        [
            {
                "cve_id": "CVE-2021-0001",
                "published_year": 2021,
                "last_modified": datetime(2026, 5, 21),
                "description": "updated correct copy",
            }
        ]
    )

    upsert_nvd_modified(
        spark,
        modified,
        output_dir=output_dir,
        snapshot_date="2026-05-21",
    )

    year_2021 = spark.read.parquet(str(output_dir / "year=2021")).collect()
    assert len(year_2021) == 1
    assert year_2021[0]["description"] == "updated correct copy"

    year_2026 = spark.read.parquet(str(output_dir / "year=2026")).collect()
    assert year_2026 == []


def test_upsert_nvd_modified_uses_configured_min_year(spark, tmp_path):
    output_dir = tmp_path / "silver" / "nvd"

    modified = spark.createDataFrame(
        [
            {
                "cve_id": "CVE-2020-0001",
                "published_year": 2020,
                "last_modified": datetime(2026, 5, 21),
                "description": "outside configured range",
            },
            {
                "cve_id": "CVE-2024-0001",
                "published_year": 2024,
                "last_modified": datetime(2026, 5, 21),
                "description": "inside configured range",
            },
        ]
    )

    stats = upsert_nvd_modified(
        spark,
        modified,
        output_dir=output_dir,
        snapshot_date="2026-05-21",
        min_year=2024,
    )

    assert stats["modified_rows"] == 1
    assert not (output_dir / "year=2020").exists()

    rows = spark.read.parquet(str(output_dir / "year=2024")).collect()
    assert [row["cve_id"] for row in rows] == ["CVE-2024-0001"]
