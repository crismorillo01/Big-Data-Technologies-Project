"""Clustering job for vulnerability pattern discovery.

Reads scored vulnerabilities from the gold layer, builds mixed features
(TF-IDF on descriptions + one-hot CWEs + one-hot vendors + numeric signals),
selects K by combining silhouette, Davies-Bouldin, and elbow metrics, fits
the final KMeans model, extracts top-keywords per cluster, and writes:
  - vulnerabilities_clustered/  (full dataset + cluster_id)
  - cluster_topics/             (cluster_id, top_keywords, top_vendors, top_cwes, size, kev_count)
  - clustering_metrics/         (K-selection comparison table)
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import List, Optional, Tuple

# Allow `spark-submit src/clustering/clustering.py` to find the src package.
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import numpy as np
from sklearn.metrics import davies_bouldin_score

from pyspark.ml.clustering import KMeans, KMeansModel
from pyspark.ml.evaluation import ClusteringEvaluator
from pyspark.ml.feature import (
    CountVectorizer,
    CountVectorizerModel,
    IDF,
    PCA,
    PCAModel,
    RegexTokenizer,
    StopWordsRemover,
    VectorAssembler,
)
from pyspark.sql import DataFrame, SparkSession
from pyspark.sql.functions import (
    array,
    col,
    collect_list,
    count,
    explode,
    lit,
    lower,
    regexp_replace,
    row_number,
    substring,
    sum as spark_sum,
    when,
)
from pyspark.sql.types import ArrayType, StringType
from pyspark.sql.window import Window

# NOTE: array() requires an active SparkContext — do NOT call it at module level.

from src.config import (
    GOLD_CLUSTER_TOPICS_DIR,
    GOLD_CLUSTERING_METRICS_DIR,
    GOLD_VULN_CLUSTERED_DIR,
    GOLD_VULN_SCORES_DIR,
    configure_logging,
    create_spark_session,
)

_log = logging.getLogger(__name__)

_DOMAIN_STOPWORDS = [
    "vulnerability", "vulnerabilities", "affected", "affects",
    "issue", "issues", "allows", "attacker", "attack",
    "remote", "local", "authenticated", "unauthenticated",
    "successful", "exploitation", "exploit", "exploited",
    "crafted", "malicious", "user", "users",
    "version", "versions", "prior", "before",
    "following", "resolved", "kernel", "linux",
    "trace", "call", "task", "error", "warning",
    "function", "file", "system", "data",
    "may", "could", "can", "using", "used",
    "product", "products", "component",
]

# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_scored_vulnerabilities(spark: SparkSession) -> DataFrame:
    """Load base-scored vulnerabilities from the gold layer."""
    _log.info("Loading scored vulnerabilities from %s", GOLD_VULN_SCORES_DIR)
    return spark.read.parquet(str(GOLD_VULN_SCORES_DIR))


# ---------------------------------------------------------------------------
# Text preprocessing
# ---------------------------------------------------------------------------

def prepare_text(df: DataFrame, description_length: int = 1000) -> DataFrame:
    """Select required columns, clean descriptions, and null-fill array columns."""
    df = df.select(
        "cve_id", "description", "cwes", "cpe_vendors",
        "cvss_score", "epss_percentile", "is_kev",
        "priority_score", "priority_level",
    ).dropna(subset=["description"])

    df = df.withColumn("description_short", substring(col("description"), 1, description_length))
    df = (
        df
        .withColumn("clean_text", lower(col("description_short")))
        .withColumn("clean_text", regexp_replace(col("clean_text"), r"\n", " "))
        .withColumn("clean_text", regexp_replace(col("clean_text"), r"http\S+", " "))
        .withColumn("clean_text", regexp_replace(col("clean_text"), r"cve-\d{4}-\d+", " "))
        .withColumn("clean_text", regexp_replace(col("clean_text"), r"0x[0-9a-f]+", " "))
        .withColumn("clean_text", regexp_replace(col("clean_text"), r"[^a-zA-Z\s]", " "))
        .withColumn("clean_text", regexp_replace(col("clean_text"), r"\s+", " "))
    )
    # Replace nulls with empty arrays so CountVectorizer receives a valid input.
    # array() requires an active SparkContext, so it is called here (not at module level).
    empty_str_arr = array().cast(ArrayType(StringType()))
    df = df.withColumn(
        "cwes", when(col("cwes").isNull(), empty_str_arr).otherwise(col("cwes"))
    )
    df = df.withColumn(
        "cpe_vendors", when(col("cpe_vendors").isNull(), empty_str_arr).otherwise(col("cpe_vendors"))
    )
    return df


# ---------------------------------------------------------------------------
# Feature engineering
# ---------------------------------------------------------------------------

def build_tfidf(
    df: DataFrame,
    vocab_size: int = 500,
    min_df: int = 20,
) -> Tuple[DataFrame, CountVectorizerModel]:
    """Tokenise descriptions and build TF-IDF sparse features."""
    tokenizer = RegexTokenizer(inputCol="clean_text", outputCol="words",
                               pattern=r"\W+", minTokenLength=3)
    df = tokenizer.transform(df)

    stopwords = list(set(StopWordsRemover.loadDefaultStopWords("english") + _DOMAIN_STOPWORDS))
    remover = StopWordsRemover(inputCol="words", outputCol="filtered_words", stopWords=stopwords)
    df = remover.transform(df)

    cv = CountVectorizer(inputCol="filtered_words", outputCol="raw_tfidf",
                         vocabSize=vocab_size, minDF=min_df)
    cv_model = cv.fit(df)
    df = cv_model.transform(df)

    idf_model = IDF(inputCol="raw_tfidf", outputCol="tfidf_features").fit(df)
    df = idf_model.transform(df)

    _log.info("TF-IDF vocabulary size: %d", len(cv_model.vocabulary))
    return df, cv_model


def build_categorical_features(df: DataFrame, vocab_size: int = 30, min_df: int = 5) -> DataFrame:
    """Build one-hot sparse vectors for top-N CWEs and vendors via CountVectorizer.

    CountVectorizer accepts array<string> columns directly — no explode needed.
    """
    cwe_cv = CountVectorizer(inputCol="cwes", outputCol="cwe_features",
                             vocabSize=vocab_size, minDF=min_df)
    df = cwe_cv.fit(df).transform(df)

    vendor_cv = CountVectorizer(inputCol="cpe_vendors", outputCol="vendor_features",
                                vocabSize=vocab_size, minDF=min_df)
    df = vendor_cv.fit(df).transform(df)
    return df


def build_numeric_features(df: DataFrame) -> DataFrame:
    """Assemble normalised numeric signals into a single dense vector."""
    df = df.withColumn("cvss_normalized", col("cvss_score") / lit(10.0))
    assembler = VectorAssembler(
        inputCols=["cvss_normalized", "epss_percentile", "is_kev"],
        outputCol="numeric_features",
        handleInvalid="keep",
    )
    return assembler.transform(df)


def assemble_features(
    df: DataFrame, use_pca: bool = True, pca_k: int = 100
) -> Tuple[DataFrame, Optional[PCAModel]]:
    """Combine TF-IDF, CWE, vendor, and numeric vectors into a single 'features' column.

    Returns the transformed DataFrame and the fitted PCAModel (or None when PCA is skipped).
    The PCAModel is needed downstream to invert centroids back to the original feature space.
    """
    assembler = VectorAssembler(
        inputCols=["tfidf_features", "cwe_features", "vendor_features", "numeric_features"],
        outputCol="assembled_features",
        handleInvalid="keep",
    )
    df = assembler.transform(df)

    if use_pca:
        _log.info("Applying PCA with k=%d", pca_k)
        pca_model = PCA(k=pca_k, inputCol="assembled_features", outputCol="features").fit(df)
        df = pca_model.transform(df)
        _log.info("PCA total explained variance: %.3f",
                  pca_model.explainedVariance.toArray().sum())
        return df, pca_model
    else:
        df = df.withColumnRenamed("assembled_features", "features")
        return df, None


# ---------------------------------------------------------------------------
# K selection
# ---------------------------------------------------------------------------

def _davies_bouldin(df_predictions: DataFrame, sample_n: int = 10_000) -> float:
    """Compute Davies-Bouldin index by sampling to Python + sklearn."""
    sample = df_predictions.select("features", "prediction").limit(sample_n).collect()
    X = np.array([row["features"].toArray() for row in sample])
    y = np.array([row["prediction"] for row in sample])
    if len(np.unique(y)) < 2:
        return float("inf")
    # davies_bouldin_score returns numpy.float64; cast to Python float for Spark createDataFrame.
    return float(davies_bouldin_score(X, y))


def evaluate_k_values(
    df: DataFrame,
    k_values: List[int],
) -> List[Tuple[int, float, float, float]]:
    """Evaluate candidate K values returning (k, silhouette, cost, davies_bouldin)."""
    evaluator = ClusteringEvaluator(featuresCol="features", predictionCol="prediction",
                                    metricName="silhouette")
    results = []
    for k in k_values:
        model = KMeans(featuresCol="features", predictionCol="prediction",
                       k=k, seed=42, maxIter=20).fit(df)
        predictions = model.transform(df)
        silhouette = float(evaluator.evaluate(predictions))
        cost = float(model.summary.trainingCost)
        db = _davies_bouldin(predictions)
        results.append((k, silhouette, cost, db))
        _log.info("K=%d | silhouette=%.4f | cost=%.2f | davies_bouldin=%.4f",
                  k, silhouette, cost, db)
    return results


def select_best_k(results: List[Tuple[int, float, float, float]]) -> int:
    """Pick K with the lowest combined rank across silhouette, cost, and Davies-Bouldin."""
    n = len(results)
    sil_order  = sorted(range(n), key=lambda i: results[i][1], reverse=True)  # higher is better
    cost_order = sorted(range(n), key=lambda i: results[i][2])                # lower is better
    db_order   = sorted(range(n), key=lambda i: results[i][3])                # lower is better

    ranks = [0] * n
    for rank, idx in enumerate(sil_order):
        ranks[idx] += rank
    for rank, idx in enumerate(cost_order):
        ranks[idx] += rank
    for rank, idx in enumerate(db_order):
        ranks[idx] += rank

    best_idx = ranks.index(min(ranks))
    best_k = results[best_idx][0]
    _log.info("K selection summary:")
    for i, (k, sil, cost, db) in enumerate(results):
        _log.info("  K=%d sil=%.3f cost=%.0f db=%.3f rank_sum=%d%s",
                  k, sil, cost, db, ranks[i], "  ← selected" if i == best_idx else "")
    return best_k


# ---------------------------------------------------------------------------
# Final model + topic extraction
# ---------------------------------------------------------------------------

def train_final_model(df: DataFrame, best_k: int) -> Tuple[DataFrame, KMeansModel]:
    """Fit the final KMeans and return (predictions_df, model)."""
    _log.info("Training final KMeans with K=%d", best_k)
    model = KMeans(featuresCol="features", predictionCol="cluster_id",
                   k=best_k, seed=42, maxIter=20).fit(df)
    return model.transform(df), model


def extract_top_keywords(
    model: KMeansModel,
    vocabulary: List[str],
    pca_model: Optional[PCAModel] = None,
    top_n: int = 10,
) -> List[List[str]]:
    """Map centroid TF-IDF weights back to vocabulary terms per cluster.

    Without PCA the assembled feature vector is:
      [tfidf (vocab_size) | cwe (30) | vendor (30) | numeric (3)]
    so centroid[:vocab_size] directly gives TF-IDF weights.

    With PCA the centroid is in the reduced k-dimensional space.
    pca_model.pc has shape (n_original_features, pca_k), so
      centroid_original ≈ pc @ centroid_pca
    reconstructs the approximate original-space centroid, whose first
    vocab_size entries are the TF-IDF weights.
    """
    centroids = model.clusterCenters()
    vocab_size = len(vocabulary)
    if pca_model is not None:
        pc = pca_model.pc.toArray()  # shape (n_original_features, pca_k)
    result = []
    for centroid in centroids:
        if pca_model is not None:
            tfidf_weights = (pc @ centroid)[:vocab_size]
        else:
            tfidf_weights = centroid[:vocab_size]
        top_indices = np.argsort(tfidf_weights)[::-1][:top_n]
        result.append([vocabulary[i] for i in top_indices])
    return result


def build_cluster_topics(
    spark: SparkSession,
    predictions_df: DataFrame,
    model: KMeansModel,
    vocabulary: List[str],
    pca_model: Optional[PCAModel] = None,
    top_n_keywords: int = 10,
    top_n_meta: int = 5,
) -> DataFrame:
    """Build the cluster_topics DataFrame."""
    keywords_per_cluster = extract_top_keywords(model, vocabulary, pca_model, top_n_keywords)
    k = len(keywords_per_cluster)

    cluster_agg = predictions_df.groupBy("cluster_id").agg(
        count("*").alias("size"),
        spark_sum("is_kev").cast("long").alias("kev_count"),
    )

    vendor_win = Window.partitionBy("cluster_id").orderBy(col("vendor_count").desc())
    top_vendors_df = (
        predictions_df
        .select("cluster_id", explode(col("cpe_vendors")).alias("vendor"))
        .groupBy("cluster_id", "vendor").agg(count("*").alias("vendor_count"))
        .withColumn("rn", row_number().over(vendor_win))
        .filter(col("rn") <= top_n_meta)
        .groupBy("cluster_id").agg(collect_list("vendor").alias("top_vendors"))
    )

    cwe_win = Window.partitionBy("cluster_id").orderBy(col("cwe_count").desc())
    top_cwes_df = (
        predictions_df
        .select("cluster_id", explode(col("cwes")).alias("cwe"))
        .groupBy("cluster_id", "cwe").agg(count("*").alias("cwe_count"))
        .withColumn("rn", row_number().over(cwe_win))
        .filter(col("rn") <= top_n_meta)
        .groupBy("cluster_id").agg(collect_list("cwe").alias("top_cwes"))
    )

    keywords_df = spark.createDataFrame(
        [(i, keywords_per_cluster[i]) for i in range(k)],
        ["cluster_id", "top_keywords"],
    )

    return (
        keywords_df
        .join(top_vendors_df, on="cluster_id", how="left")
        .join(top_cwes_df,    on="cluster_id", how="left")
        .join(cluster_agg,    on="cluster_id", how="left")
    )


# ---------------------------------------------------------------------------
# Saving outputs
# ---------------------------------------------------------------------------

def save_outputs(
    spark: SparkSession,
    full_df: DataFrame,
    predictions_df: DataFrame,
    topics_df: DataFrame,
    metrics: List[Tuple[int, float, float, float]],
) -> None:
    """Write clustered dataset, cluster topics, and K-selection metrics."""
    cluster_ids = predictions_df.select("cve_id", "cluster_id")
    clustered_df = full_df.join(cluster_ids, on="cve_id", how="left")

    _log.info("Writing clustered vulnerabilities to %s", GOLD_VULN_CLUSTERED_DIR)
    clustered_df.write.mode("overwrite").parquet(str(GOLD_VULN_CLUSTERED_DIR))

    _log.info("Writing cluster topics to %s", GOLD_CLUSTER_TOPICS_DIR)
    topics_df.write.mode("overwrite").parquet(str(GOLD_CLUSTER_TOPICS_DIR))

    _log.info("Writing clustering metrics to %s", GOLD_CLUSTERING_METRICS_DIR)
    spark.createDataFrame(metrics, ["k", "silhouette", "cost", "davies_bouldin"]).write.mode(
        "overwrite"
    ).parquet(str(GOLD_CLUSTERING_METRICS_DIR))

    _log.info("Cluster sizes:")
    clustered_df.groupBy("cluster_id").count().orderBy("cluster_id").show()


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run_clustering(
    spark: SparkSession,
    k_values: List[int],
    description_length: int = 1000,
    vocab_size: int = 500,
    min_df: int = 20,
    use_pca: bool = True,
    pca_k: int = 100,
) -> None:
    """Run the full clustering pipeline end-to-end."""
    full_df = load_scored_vulnerabilities(spark)

    df = prepare_text(full_df, description_length)
    df, cv_model = build_tfidf(df, vocab_size, min_df)
    df = build_categorical_features(df)
    df = build_numeric_features(df)
    df, pca_model = assemble_features(df, use_pca=use_pca, pca_k=pca_k)
    df.cache()

    metrics = evaluate_k_values(df, k_values)
    best_k = select_best_k(metrics)

    predictions_df, model = train_final_model(df, best_k)
    topics_df = build_cluster_topics(spark, predictions_df, model, cv_model.vocabulary, pca_model)

    save_outputs(spark, full_df, predictions_df, topics_df, metrics)
    df.unpersist()
    _log.info("Clustering job complete.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run vulnerability clustering job.")
    parser.add_argument("--k-values", nargs="+", type=int, default=[4, 6, 8, 10, 12])
    parser.add_argument("--description-length", type=int, default=1000)
    parser.add_argument("--vocab-size", type=int, default=500)
    parser.add_argument("--min-df",     type=int, default=20)
    parser.add_argument("--pca-k",      type=int, default=100)
    parser.add_argument("--no-pca",     action="store_true",
                        help="Skip PCA and pass assembled features directly to KMeans.")
    parser.add_argument("--driver-memory", default="3g",
                        help="Spark driver memory (e.g. 3g). Default: 3g.")
    return parser.parse_args()


def main() -> None:
    configure_logging()
    args = parse_args()
    spark = create_spark_session("vulnerability-clustering", driver_memory=args.driver_memory)
    try:
        run_clustering(
            spark,
            k_values=args.k_values,
            description_length=args.description_length,
            vocab_size=args.vocab_size,
            min_df=args.min_df,
            use_pca=not args.no_pca,
            pca_k=args.pca_k,
        )
    finally:
        spark.stop()


if __name__ == "__main__":
    main()
