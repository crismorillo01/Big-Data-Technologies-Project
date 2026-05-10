"""Tests for src/utils/http.py.

We do not test ``download_file`` directly because that would require
mocking ``requests`` and contributes little — the function is a thin
wrapper around well-known libraries. We do test ``gunzip_file`` because
its idempotence and ``force`` semantics are easy to break in a refactor
and easy to verify without network or mocking.
"""

from __future__ import annotations

import gzip
from pathlib import Path

import pytest

from src.utils.http import gunzip_file


@pytest.fixture
def gzipped_file(tmp_path: Path) -> tuple[Path, Path, bytes]:
    """Create a small ``.gz`` file and return ``(gz_path, target_path, expected_bytes)``."""
    payload = b"cve_id,score\nCVE-2024-0001,0.42\n"
    gz_path = tmp_path / "sample.csv.gz"
    target = tmp_path / "sample.csv"
    with gzip.open(gz_path, "wb") as f:
        f.write(payload)
    return gz_path, target, payload


def test_gunzip_file_extracts_correctly(gzipped_file):
    gz_path, target, payload = gzipped_file
    out = gunzip_file(gz_path, target)
    assert out == target
    assert target.read_bytes() == payload


def test_gunzip_file_is_idempotent_when_target_exists(gzipped_file):
    """A second call must not re-extract; we verify by tampering with the target."""
    gz_path, target, _ = gzipped_file
    gunzip_file(gz_path, target)

    # Overwrite the extracted file with a sentinel. With force=False the helper
    # should leave it alone (idempotent skip).
    target.write_bytes(b"SENTINEL")
    gunzip_file(gz_path, target, force=False)
    assert target.read_bytes() == b"SENTINEL"


def test_gunzip_file_force_overwrites_existing(gzipped_file):
    gz_path, target, payload = gzipped_file
    target.write_bytes(b"SENTINEL")
    gunzip_file(gz_path, target, force=True)
    assert target.read_bytes() == payload


def test_gunzip_file_creates_parent_directories(tmp_path: Path):
    payload = b"x"
    gz_path = tmp_path / "a.txt.gz"
    with gzip.open(gz_path, "wb") as f:
        f.write(payload)

    nested_target = tmp_path / "deep" / "deeper" / "out.txt"
    assert not nested_target.parent.exists()

    gunzip_file(gz_path, nested_target)
    assert nested_target.read_bytes() == payload
