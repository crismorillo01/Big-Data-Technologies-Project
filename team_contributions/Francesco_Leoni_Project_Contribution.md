# Francesco Leoni Contribution

This document summarises the part of the project completed by Francesco Leoni.
This block focuses on data quality assessment, vulnerability priority scoring,
unsupervised clustering, and cluster-aware risk score refinement.

## Block Summary

| Member | Main slice | Current files |
|---|---|---|
| Francesco Leoni | Data quality, scoring, clustering | `src/processing/data_quality.py`, `src/scoring/priority_scoring.py`, `src/clustering/clustering.py`, `src/scoring/cluster_aware_scoring.py` |

## What Each File Does

| File | Contribution |
|---|---|
| `src/processing/data_quality.py` | Reads the gold master dataset and computes a set of completeness and distribution metrics per snapshot: null rates for CVSS, EPSS, CWEs, and CPE fields; severity distribution; KEV counts; and EPSS statistics. Results are written to `data/gold/data_quality/` partitioned by snapshot date. |
| `src/scoring/priority_scoring.py` | Assigns a numeric priority score to every CVE by combining four signals: normalised CVSS score, EPSS percentile, KEV membership flag, and a recency factor that decays linearly over three years. CVEs in the KEV catalogue receive a score floor so they are never ranked below a minimum threshold. A categorical level (Critical / High / Medium / Low) is derived from the final score. |
| `src/clustering/clustering.py` | Groups vulnerabilities into thematic clusters using unsupervised machine learning. It builds mixed features from CVE description text (TF-IDF), weakness types (CWE), affected vendors, and numeric risk signals, then applies PCA for dimensionality reduction and KMeans for clustering. The best number of clusters is selected automatically using silhouette, Davies-Bouldin, and elbow metrics combined. For each cluster the top keywords, top vendors, and top CWEs are extracted and written to the gold layer. |
| `src/scoring/cluster_aware_scoring.py` | Refines the base priority score produced by `priority_scoring.py` by incorporating cluster-level risk signals: KEV density and maximum EPSS score within each cluster. CVEs that belong to high-risk clusters receive a boosted final score, reflecting the idea that a vulnerability is more urgent when it sits alongside many other dangerous ones. |

## Selected Variables

### Data Quality Metrics (`data_quality.py`)

| Variable | Meaning |
|---|---|
| `snapshot_date` | Pipeline execution date that identifies the metrics snapshot. |
| `row_count` | Total number of CVEs in the master dataset for that snapshot. |
| `distinct_cve_count` | Number of unique CVE identifiers, used to detect duplicates. |
| `pct_null_cvss` | Percentage of CVEs with no CVSS score available. |
| `pct_null_epss` | Percentage of CVEs with no EPSS score available. |
| `pct_null_cwes` | Percentage of CVEs with no weakness type (CWE) information. |
| `pct_null_cpe` | Percentage of CVEs with no vendor/product (CPE) information. |
| `pct_epss_gt_07` | Percentage of CVEs with an EPSS score above 0.7 (high exploitability). |
| `pct_epss_gt_09` | Percentage of CVEs with an EPSS score above 0.9 (very high exploitability). |
| `mean_epss` | Average EPSS score across all CVEs in the snapshot. |
| `median_epss` | Median EPSS score, less sensitive to outliers than the mean. |
| `kev_count` | Total number of CVEs present in the CISA KEV catalogue. |
| `nvd_kev_intersection` | Number of CVEs that appear in both NVD and KEV. |
| `nvd_epss_intersection` | Number of CVEs that appear in both NVD and EPSS. |
| `nvd_kev_epss_intersection` | Number of CVEs present in all three sources simultaneously. |

### Priority Scoring (`priority_scoring.py`)

| Variable | Meaning |
|---|---|
| `cvss_normalized` | CVSS base score rescaled to the range [0, 1] by dividing by 10. |
| `recency_score` | Linear decay factor: 1.0 for CVEs published today, 0.0 for those published three or more years ago. |
| `priority_score` | Weighted combination of `cvss_normalized`, `epss_percentile`, `is_kev`, and `recency_score`. |
| `priority_level` | Categorical risk label derived from `priority_score`: Critical, High, Medium, or Low. |

### Clustering (`clustering.py`)

| Variable | Meaning |
|---|---|
| `cluster_id` | Integer label identifying the cluster each CVE belongs to. |
| `top_keywords` | Most representative words from CVE descriptions within the cluster (TF-IDF). |
| `top_vendors` | Most frequently affected vendors within the cluster. |
| `top_cwes` | Most frequent weakness types (CWE) within the cluster. |
| `size` | Total number of CVEs in the cluster. |
| `kev_count` | Number of KEV CVEs in the cluster. |

### Cluster-Aware Scoring (`cluster_aware_scoring.py`)

| Variable | Meaning |
|---|---|
| `cluster_kev_density` | Share of KEV CVEs within the cluster, measuring how dangerous the cluster is as a whole. |
| `cluster_epss_max` | Highest EPSS score observed within the cluster. |
| `cluster_epss_mean` | Average EPSS score within the cluster. |
| `cluster_avg_cvss` | Average CVSS score within the cluster. |
| `priority_score_final` | Final priority score after applying the cluster-level boost, clipped to a maximum value. |
| `priority_level_final` | Final categorical label (Critical / High / Medium / Low) based on `priority_score_final`. |
