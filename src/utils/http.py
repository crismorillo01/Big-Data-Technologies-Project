"""HTTP and archive helpers shared by every ingestion job.

The three ingestion scripts (NVD, KEV, EPSS) used to each define their own
``download_file`` and (in two of them) ``gunzip_file``. This module is the
single replacement: download with retries, idempotent extraction, and a
cheap ``url_exists`` check used by the EPSS date scanner.

Design notes
------------
- ``download_file`` writes to a ``.part`` temp file and atomically renames
  on success. A half-downloaded file is never visible to ``force=False``
  callers, which would otherwise silently reuse a corrupt artifact.
- Retries (tenacity) target transient failures only: ``RequestException``
  (DNS, timeout, connection reset) and HTTP 5xx. We do **not** retry 4xx
  because those are permanent (404, 403, …) and retrying just wastes time.
- ``url_exists`` does not retry: it is used by the EPSS scanner to walk
  back through candidate dates, where a ``False`` is part of the normal
  control flow, not a failure.
"""

from __future__ import annotations

import gzip
import logging
import shutil
from pathlib import Path
from typing import Union

import requests
from tenacity import (
    before_sleep_log,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)


logger = logging.getLogger(__name__)

PathLike = Union[str, Path]


class HttpServerError(requests.HTTPError):
    """HTTP 5xx — surfaced as a distinct type so tenacity can match it."""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _raise_for_status(response: requests.Response) -> None:
    """Raise ``HttpServerError`` on 5xx, plain ``HTTPError`` on 4xx."""
    if 500 <= response.status_code < 600:
        raise HttpServerError(
            f"HTTP {response.status_code} for {response.url}",
            response=response,
        )
    response.raise_for_status()


@retry(
    reraise=True,
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=2, min=2, max=10),
    retry=retry_if_exception_type((requests.RequestException, HttpServerError)),
    before_sleep=before_sleep_log(logger, logging.WARNING),
)
def _download_with_retry(
    url: str,
    output_path: Path,
    chunk_size: int,
    timeout: int,
) -> None:
    """Stream a URL to a local file with atomic rename on success."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = output_path.with_suffix(output_path.suffix + ".part")

    with requests.get(url, stream=True, timeout=timeout) as response:
        _raise_for_status(response)
        with open(tmp_path, "wb") as fh:
            for chunk in response.iter_content(chunk_size=chunk_size):
                if chunk:
                    fh.write(chunk)

    # Atomic move: only after the full body is written do we expose the
    # final filename. Crashes mid-download leave a .part behind, never a
    # truncated final file.
    tmp_path.replace(output_path)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def download_file(
    url: str,
    output_path: PathLike,
    force: bool = False,
    chunk_size: int = 8192,
    timeout: int = 120,
) -> Path:
    """Download ``url`` to ``output_path`` with retries.

    Parameters
    ----------
    url :
        Source URL.
    output_path :
        Destination path. Parent directories are created if needed.
    force :
        If ``False`` (default) and the destination already exists, the
        download is skipped and the existing file is returned.
    chunk_size :
        Streaming chunk size in bytes.
    timeout :
        Per-request timeout in seconds (applies to the whole streamed
        response, not just the connect phase).

    Returns
    -------
    Path
        The destination path (always as a :class:`pathlib.Path`).
    """
    output_path = Path(output_path)

    if output_path.exists() and not force:
        logger.info("File already present, skipping download: %s", output_path)
        return output_path

    logger.info("Downloading %s -> %s", url, output_path)
    _download_with_retry(url, output_path, chunk_size=chunk_size, timeout=timeout)
    logger.info("Downloaded %s (%d bytes)", output_path, output_path.stat().st_size)
    return output_path


def gunzip_file(
    input_path: PathLike,
    output_path: PathLike,
    force: bool = False,
) -> Path:
    """Extract a ``.gz`` archive to ``output_path``.

    Idempotent: if the destination already exists and ``force`` is
    ``False``, returns immediately without re-extracting.
    """
    input_path = Path(input_path)
    output_path = Path(output_path)

    if output_path.exists() and not force:
        logger.info("Extracted file already present, skipping: %s", output_path)
        return output_path

    output_path.parent.mkdir(parents=True, exist_ok=True)
    logger.info("Extracting %s -> %s", input_path, output_path)

    with gzip.open(input_path, "rb") as src, open(output_path, "wb") as dst:
        shutil.copyfileobj(src, dst)

    return output_path


def url_exists(url: str, timeout: int = 10) -> bool:
    """Return ``True`` if ``url`` responds with HTTP 200, else ``False``.

    Tries ``HEAD`` first (cheap) and falls back to a streamed ``GET``
    because some servers — notably the EPSS CDN — do not implement
    ``HEAD`` reliably. Does **not** retry: this function is used by the
    EPSS date scanner to walk back through candidate dates and a clean
    ``False`` is part of the normal control flow.
    """
    try:
        response = requests.head(url, timeout=timeout, allow_redirects=True)
        if response.status_code == 200:
            return True
        # Fallback for servers that 4xx HEAD requests but accept GET.
        response = requests.get(url, stream=True, timeout=timeout)
        return response.status_code == 200
    except requests.RequestException:
        return False
