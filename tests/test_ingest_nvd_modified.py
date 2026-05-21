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
