"""Master vulnerability dataset — joins NVD + KEV + EPSS into gold.

This job is the boundary between ingestion and analytics. It pulls the
three silver datasets, normalizes them around ``cve_id``, and produces a
single Parquet table partitioned by ``published_year`` and
``snapshot_date``. Everything downstream (data quality, scoring,
clustering, simulation) reads from here.

Output gold schema (master_vulnerabilities)
-------------------------------------------

Identity & timing:
- ``cve_id``                : string (key)
- ``published``             : timestamp
- ``last_modified``         : timestamp
- ``published_year``        : int (partition)
- ``snapshot_date``         : date (partition; today UTC)

Description & taxonomy (NVD):
- ``description``           : string
- ``cwes``                  : array<string>

Severity (NVD, with v4 → v3.1 → v3.0 → v2 fallback):
- ``cvss_score``            : double
- ``cvss_severity``         : string
- ``cvss_version``          : string

Affected products (NVD CPE):
- ``cpe_vendors``           : array<string>
- ``cpe_products``          : array<string>
- ``cpe_versions``          : array<string>

Exploit references (NVD):
- ``reference_count``       : int
- ``has_exploit_reference`` : boolean

Active exploitation (CISA KEV):
- ``is_kev``                : int (0 or 1)
- ``kev_date_added``        : date
- ``kev_vendor``            : string
- ``kev_product``           : string
- ``kev_vulnerability_name``: string
- ``kev_short_description`` : string
- ``kev_required_action``   : string
- ``known_ransomware_campaign_use`` : string (raw "Known"/"Unknown"/etc.)
- ``is_ransomware``         : boolean

Probability of exploitation (EPSS, snapshot-aligned):
- ``epss_score``            : double (0 if not in EPSS)
- ``epss_percentile``       : double (0 if not in EPSS)
- ``epss_score_date``       : date (which EPSS snapshot was used; null if no EPSS)

Derived for downstream grouping:
- ``primary_vendor``        : string (NVD CPE first vendor, falling back to KEV vendor)
- ``primary_product``       : string (NVD CPE first product, falling back to KEV product)
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

# Allow plain-script execution: `spark-submit src/processing/join_master.py`
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from pyspark.sql import DataFrame, SparkSession
from pyspark.sql.functions import (
    coalesce,
    col,
    element_at,
    lit,
    to_date,
)
from pyspark.sql.functions import max as spark_max
from pyspark.sql.types import IntegerType

from src.config import (  # noqa: E402
    GOLD_MASTER_DIR,
    SILVER_EPSS_DIR,
    SILVER_KEV_DIR,
    SILVER_NVD_DELTA_DIR,
    SILVER_NVD_DIR,
    configure_logging,
    create_spark_session,
    get_snapshot_date,
)


logger = logging.getLogger(__name__)

NVD_STORAGE_PARQUET = "parquet"
NVD_STORAGE_DELTA = "delta"


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def load_nvd(
    spark: SparkSession,
    silver_nvd_dir: Path,
    silver_nvd_delta_dir: Path = SILVER_NVD_DELTA_DIR,
    nvd_storage: str = NVD_STORAGE_DELTA,
) -> DataFrame:
    """Read every NVD year partition under the silver layer."""
    if nvd_storage == NVD_STORAGE_DELTA:
        logger.info("Loading NVD silver Delta table from %s", silver_nvd_delta_dir)
        return spark.read.format("delta").load(str(silver_nvd_delta_dir))

    logger.info("Loading NVD silver Parquet mirror from %s", silver_nvd_dir)
    return spark.read.parquet(str(silver_nvd_dir))


def load_kev(spark: SparkSession, silver_kev_dir: Path) -> DataFrame:
    """Read the KEV silver dataset."""
    logger.info("Loading KEV silver from %s", silver_kev_dir)
    return spark.read.parquet(str(silver_kev_dir))


def load_epss_for_snapshot(
    spark: SparkSession,
    silver_epss_dir: Path,
    snapshot_date: str,
) -> DataFrame:
    """Read the latest EPSS partition available at or before ``snapshot_date``.

    The master snapshot must not use exploitability signals from the
    future. For example, a master run stamped ``2026-05-14`` may use EPSS
    ``2026-05-14`` or an earlier available partition, but never
    ``2026-05-16``.
    """
    logger.info("Loading EPSS silver from %s", silver_epss_dir)
    epss_all = spark.read.parquet(str(silver_epss_dir))
    epss_as_of_snapshot = epss_all.where(
        col("score_date") <= lit(snapshot_date).cast("date")
    )
    latest_row = epss_as_of_snapshot.agg(spark_max("score_date").alias("latest")).collect()[0]
    latest_date = latest_row["latest"]

    if latest_date is None:
        logger.warning(
            "No EPSS partition found at or before snapshot_date=%s; "
            "the master will have null EPSS columns.",
            snapshot_date,
        )
        return epss_all.limit(0)  # empty, but with the right schema

    logger.info("Using EPSS partition score_date=%s for snapshot_date=%s", latest_date, snapshot_date)
    return epss_as_of_snapshot.where(col("score_date") == lit(latest_date))


# ---------------------------------------------------------------------------
# Per-source preparation (renaming + flag columns)
# ---------------------------------------------------------------------------

def prepare_kev(kev_df: DataFrame) -> DataFrame:
    """Rename KEV columns with a ``kev_`` prefix and add the ``is_kev`` flag.

    The ``kev_`` prefix prevents column-name collisions in the downstream
    join (the original KEV columns ``vendor_project`` and ``product``
    would otherwise be hard to disambiguate from the NVD-derived
    ``primary_vendor`` and ``primary_product``).
    """
    return (
        kev_df
        .select(
            col("cve_id"),
            col("kev_date_added"),
            col("vendor_project").alias("kev_vendor"),
            col("product").alias("kev_product"),
            col("vulnerability_name").alias("kev_vulnerability_name"),
            col("short_description").alias("kev_short_description"),
            col("required_action").alias("kev_required_action"),
            col("known_ransomware_campaign_use"),
            col("is_ransomware"),
        )
        .withColumn("is_kev", lit(1).cast(IntegerType()))
    )


def prepare_epss(epss_df: DataFrame) -> DataFrame:
    """Rename ``score_date`` to ``epss_score_date`` so the join keeps it explicitly."""
    return (
        epss_df
        .select(
            col("cve_id"),
            col("epss_score"),
            col("epss_percentile"),
            col("score_date").alias("epss_score_date"),
        )
    )


# ---------------------------------------------------------------------------
# Master assembly
# ---------------------------------------------------------------------------

def build_master_dataset(
    nvd_df: DataFrame,
    kev_df: DataFrame,
    epss_df: DataFrame,
    snapshot_date_str: str,
) -> DataFrame:
    """Left-join NVD with KEV and the selected EPSS snapshot."""
    kev_prepared = prepare_kev(kev_df)
    epss_prepared = prepare_epss(epss_df)

    logger.info("Joining NVD ⟕ KEV ⟕ EPSS")
    master = (
        nvd_df
        .join(kev_prepared, on="cve_id", how="left")
        .join(epss_prepared, on="cve_id", how="left")
        # Replace null KEV/EPSS with sensible defaults so downstream code does not
        # have to special-case "no signal" rows.
        .withColumn("is_kev", coalesce(col("is_kev"), lit(0).cast(IntegerType())))
        .withColumn("is_ransomware", coalesce(col("is_ransomware"), lit(False)))
        .withColumn("epss_score", coalesce(col("epss_score"), lit(0.0)))
        .withColumn("epss_percentile", coalesce(col("epss_percentile"), lit(0.0)))
        # Snapshot date — partition column. Stamped here, not derived from data,
        # so re-runs on the same day overwrite the same partition.
        .withColumn("snapshot_date", to_date(lit(snapshot_date_str), "yyyy-MM-dd"))
        # Derived primary vendor/product: NVD CPE first, KEV as fallback.
        # element_at on an empty or null array returns null, so coalesce works.
        .withColumn(
            "primary_vendor",
            coalesce(element_at(col("cpe_vendors"), 1), col("kev_vendor")),
        )
        .withColumn(
            "primary_product",
            coalesce(element_at(col("cpe_products"), 1), col("kev_product")),
        )
    )
    return master


# ---------------------------------------------------------------------------
# Write
# ---------------------------------------------------------------------------

def save_master(df: DataFrame, output_dir: Path) -> int:
    """Write partitioned by ``published_year`` and ``snapshot_date``."""
    output_dir.mkdir(parents=True, exist_ok=True)
    df.cache()
    try:
        n_rows = df.count()
        logger.info("Writing master (%d rows) to %s", n_rows, output_dir)
        (
            df
            .write
            .mode("overwrite")
            .partitionBy("published_year", "snapshot_date")
            .parquet(str(output_dir))
        )
    finally:
        df.unpersist(blocking=True)
    return n_rows


# ---------------------------------------------------------------------------
# Job entry
# ---------------------------------------------------------------------------

def run_master_build(
    spark: SparkSession,
    silver_nvd_dir: Path = SILVER_NVD_DIR,
    silver_nvd_delta_dir: Path = SILVER_NVD_DELTA_DIR,
    nvd_storage: str = NVD_STORAGE_DELTA,
    silver_kev_dir: Path = SILVER_KEV_DIR,
    silver_epss_dir: Path = SILVER_EPSS_DIR,
    output_dir: Path = GOLD_MASTER_DIR,
    snapshot_date_str: str | None = None,
) -> int:
    """Build and persist the master dataset. Returns row count written."""
    snapshot = snapshot_date_str or get_snapshot_date()
    logger.info("Master build snapshot_date=%s", snapshot)
    logger.info("NVD silver storage mode: %s", nvd_storage)

    nvd_df = load_nvd(
        spark,
        silver_nvd_dir=silver_nvd_dir,
        silver_nvd_delta_dir=silver_nvd_delta_dir,
        nvd_storage=nvd_storage,
    )
    kev_df = load_kev(spark, silver_kev_dir)
    epss_df = load_epss_for_snapshot(spark, silver_epss_dir, snapshot)

    master = build_master_dataset(nvd_df, kev_df, epss_df, snapshot)
    return save_master(master, output_dir)


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Build the master vulnerability dataset (NVD ⟕ KEV ⟕ snapshot-aligned EPSS)."
    )
    parser.add_argument("--silver-nvd", type=Path, default=SILVER_NVD_DIR)
    parser.add_argument("--silver-nvd-delta", type=Path,
                        default=SILVER_NVD_DELTA_DIR)
    parser.add_argument(
        "--nvd-storage",
        choices=[NVD_STORAGE_PARQUET, NVD_STORAGE_DELTA],
        default=NVD_STORAGE_DELTA,
        help="NVD silver storage engine. Default: delta. Use parquet for legacy Parquet mirror.",
    )
    parser.add_argument("--silver-kev", type=Path, default=SILVER_KEV_DIR)
    parser.add_argument("--silver-epss", type=Path, default=SILVER_EPSS_DIR)
    parser.add_argument("--output-dir", type=Path, default=GOLD_MASTER_DIR)
    parser.add_argument(
        "--snapshot-date",
        default=None,
        help="Snapshot date (YYYY-MM-DD). Default: today UTC.",
    )
    parser.add_argument("--driver-memory", default="3g")
    return parser.parse_args()


def main() -> None:
    """Entry point for ``python -m src.processing.join_master`` and ``spark-submit``."""
    configure_logging()
    args = parse_args()

    spark = create_spark_session(
        app_name="master-dataset",
        driver_memory=args.driver_memory,
        enable_delta=args.nvd_storage == NVD_STORAGE_DELTA,
    )
    try:
        run_master_build(
            spark=spark,
            silver_nvd_dir=args.silver_nvd,
            silver_nvd_delta_dir=args.silver_nvd_delta,
            nvd_storage=args.nvd_storage,
            silver_kev_dir=args.silver_kev,
            silver_epss_dir=args.silver_epss,
            output_dir=args.output_dir,
            snapshot_date_str=args.snapshot_date,
        )
    finally:
        spark.stop()


if __name__ == "__main__":
    main()
