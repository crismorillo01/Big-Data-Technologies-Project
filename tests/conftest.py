"""Shared pytest fixtures for the test suite.

Every test that needs Spark uses the ``spark`` fixture below. It boots a
single ``local[1]`` session per test session (not per test) because
spinning up a JVM per test is unbearable.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterator

import pytest
from pyspark.sql import SparkSession


# Make ``from src.x import y`` work in tests no matter where pytest is run from.
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


@pytest.fixture(scope="session")
def spark() -> Iterator[SparkSession]:
    """Tiny Spark session for unit tests.

    ``local[1]`` (one core) and 1g driver memory are deliberate: the
    test data is microscopic and we want the JVM start-up to be as
    cheap as possible. The Spark UI is disabled because nothing in CI
    is going to look at it.
    """
    session = (
        SparkSession.builder
        .appName("vuln-intel-tests")
        .master("local[1]")
        .config("spark.driver.memory", "1g")
        .config("spark.sql.shuffle.partitions", "2")
        .config("spark.ui.enabled", "false")
        .config("spark.serializer", "org.apache.spark.serializer.KryoSerializer")
        .config("spark.sql.sources.partitionOverwriteMode", "dynamic")
        .getOrCreate()
    )
    session.sparkContext.setLogLevel("ERROR")
    yield session
    session.stop()
