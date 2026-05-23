# Cristina Morillo Contribution

This document summarises the part of the project completed by Cristina Morillo.
This block focuses on the project infrastructure, data ingestion, master table
construction, pipeline orchestration, and Docker packaging.

## Block Summary

| Member | Main slice | Current files |
|---|---|---|
| Cristina Morillo | Infrastructure, ingestion, master, pipeline, Docker | `src/config.py`, `src/utils/http.py`, `src/ingestion/*`, `src/processing/join_master.py`, `src/pipeline/daily_pipeline.py`, `Dockerfile`, `docker-compose.yml`, `docker-entrypoint.sh` |

## What Each File Does

| File | Contribution |
|---|---|
| `src/config.py` | Centralises project paths, `raw/silver/gold` folders, default pipeline values, Spark session creation, and a helper for snapshot dates. It avoids hardcoded paths across the codebase. |
| `src/utils/http.py` | Reuses the download and decompression logic for NVD, KEV, and EPSS. It includes retries, atomic writes, and URL existence checks. |
| `src/ingestion/ingest_nvd.py` | Downloads the yearly NVD feeds, transforms them into a clean schema, and writes the silver layer partitioned by year. It extracts CVE, CVSS, CWE, CPE, and reference data. |
| `src/ingestion/ingest_nvd_modified.py` | Handles the NVD `modified` feed for incremental loads. It deduplicates updates, preserves lineage, and updates the silver layer without rebuilding the full history. |
| `src/ingestion/ingest_kev.py` | Ingests the CISA KEV catalogue, standardises column names, converts types, and generates the `is_ransomware` flag. |
| `src/ingestion/ingest_epss.py` | Downloads a daily EPSS snapshot, selects the most recent available date, and stores the history in `score_date` partitions. |
| `src/processing/join_master.py` | Joins NVD + KEV + EPSS into a single gold table called `master_vulnerabilities`. It also fills default values, computes `primary_vendor` and `primary_product`, and sets `snapshot_date`. |
| `src/pipeline/daily_pipeline.py` | Orchestrates the end-to-end execution. It decides whether to run a full NVD refresh or an incremental update, then executes the steps in the correct order. |
| `Dockerfile` | Defines the project base image with Python, Java, and runtime dependencies. It allows both the Streamlit app and the Spark pipeline to run inside containers. |
| `docker-compose.yml` | Starts the `app` and `pipeline` services using the same image and the same data volume. It makes the web app and processing workflow easy to run locally. |
| `docker-entrypoint.sh` | Acts as the command selector inside the container. Depending on the argument, it launches Streamlit, the daily pipeline, or an interactive shell. |

## Selected Dataset Variables

This table summarises the variables preserved or derived in the ingestion and master-building part of the project.

### NVD

| Variable | Meaning |
|---|---|
| `cve_id` | Unique vulnerability identifier. It is normalised to uppercase and trimmed. |
| `published` | Publication date and time of the CVE in NVD. |
| `last_modified` | Date and time of the last update to the record. |
| `published_year` | Year derived from `published`, used for partitioning and filtering. |
| `description` | Main English description of the CVE. |
| `cwes` | List of CWE values associated with the CVE, deduplicated and filtered to keep only `CWE-*` entries. |
| `cvss_score` | Selected CVSS base score using the fallback chain `v4.0 -> v3.1 -> v3.0 -> v2`. |
| `cvss_severity` | Textual severity associated with the selected CVSS score. |
| `cvss_version` | CVSS version used to calculate the score. |
| `cpe_vendors` | List of affected CPE vendors. |
| `cpe_products` | List of affected CPE products. |
| `cpe_versions` | List of affected CPE versions. |
| `reference_count` | Total number of references associated with the CVE. |
| `has_exploit_reference` | Indicates whether any reference is tagged as `Exploit`. |

### KEV

| Variable | Meaning |
|---|---|
| `cve_id` | CVE identifier appearing in the KEV catalogue. |
| `vendor_project` | Vendor or project name reported by CISA in the catalogue. |
| `product` | Affected product according to KEV. |
| `vulnerability_name` | Short vulnerability name in KEV. |
| `kev_date_added` | Date when CISA added the CVE to the catalogue. |
| `short_description` | Brief description of the issue. |
| `required_action` | Recommended mitigation action from CISA. |
| `known_ransomware_campaign_use` | Original text field describing ransomware campaign use. |
| `is_ransomware` | Boolean flag derived from the previous field, `True` when the value is `Known`. |

### EPSS

| Variable | Meaning |
|---|---|
| `cve_id` | CVE identifier to which the EPSS score is assigned. |
| `epss_score` | EPSS estimated exploitation probability, in the range `[0, 1]`. |
| `epss_percentile` | Percentile of the EPSS score compared with the rest of the CVE universe. |
| `score_date` | Date of the EPSS snapshot used. |

### Derived Master Variables

| Variable | Meaning |
|---|---|
| `is_kev` | Binary indicator of membership in the KEV catalogue. |
| `kev_vendor` | KEV vendor renamed with a prefix to avoid collisions. |
| `kev_product` | KEV product renamed with a prefix to avoid collisions. |
| `kev_vulnerability_name` | Vulnerability name coming from KEV. |
| `kev_short_description` | Short description coming from KEV. |
| `kev_required_action` | Recommended action coming from KEV. |
| `epss_score_date` | EPSS snapshot date selected for the master snapshot. |
| `snapshot_date` | Pipeline execution date, used as the output partition. |
| `primary_vendor` | Main vendor used for grouping, prioritising NVD and falling back to KEV when needed. |
| `primary_product` | Main product used for grouping, prioritising NVD and falling back to KEV when needed. |
