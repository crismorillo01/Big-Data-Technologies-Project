"""Clustering job for vulnerability pattern discovery.

This script reads scored vulnerabilities from the gold layer, preprocesses
vulnerability descriptions, converts text into TF-IDF features, reduces
feature dimensionality with PCA, selects the best K using silhouette score,
and writes clustered vulnerabilities back to the gold layer.
"""

import argparse
from typing import List, Tuple

from pyspark.ml.clustering import KMeans
from pyspark.ml.evaluation import ClusteringEvaluator
from pyspark.ml.feature import CountVectorizer, IDF, PCA, RegexTokenizer, StopWordsRemover
from pyspark.sql import DataFrame, SparkSession
from pyspark.sql.functions import avg, col, lower, regexp_replace, substring, sum as spark_sum


DEFAULT_STOPWORDS = [
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


def create_spark_session(app_name: str = "vulnerability-clustering") -> SparkSession:
    """Create the Spark session used by the clustering job."""
    spark = (
        SparkSession.builder
        .appName(app_name)
        .config("spark.driver.memory", "6g")
        .config("spark.executor.memory", "6g")
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("WARN")
    return spark


def load_scored_vulnerabilities(spark: SparkSession, input_path: str) -> DataFrame:
    """Load scored vulnerabilities from the gold layer."""
    print(f"Loading scored vulnerabilities from: {input_path}")
    return spark.read.parquet(input_path)


def prepare_text_dataset(df: DataFrame, description_length: int = 1000) -> DataFrame:
    """Select relevant columns and clean vulnerability descriptions."""
    df_text = (
        df.select("cve_id", "description", "cwe",
                  "cvss_severity", "priority_score")
        .dropna(subset=["description"])
    )

    # Keep only the beginning of long advisories to reduce noise and memory usage.
    df_text = df_text.withColumn(
        "description_short",
        substring(col("description"), 1, description_length),
    )

    # Normalize text and remove high-noise patterns.
    df_text = (
        df_text
        .withColumn("clean_text", lower(col("description_short")))
        .withColumn("clean_text", regexp_replace(col("clean_text"), r"\n", " "))
        .withColumn("clean_text", regexp_replace(col("clean_text"), r"http\S+", " "))
        .withColumn("clean_text", regexp_replace(col("clean_text"), r"cve-\d{4}-\d+", " "))
        .withColumn("clean_text", regexp_replace(col("clean_text"), r"0x[0-9a-f]+", " "))
        .withColumn("clean_text", regexp_replace(col("clean_text"), r"[^a-zA-Z\s]", " "))
        .withColumn("clean_text", regexp_replace(col("clean_text"), r"\s+", " "))
    )

    return df_text


def build_text_features(
    df_text: DataFrame,
    vocab_size: int = 2000,
    min_df: int = 20,
) -> Tuple[DataFrame, CountVectorizer, IDF]:
    """Tokenize descriptions and build TF-IDF features."""
    tokenizer = RegexTokenizer(
        inputCol="clean_text",
        outputCol="words",
        pattern="\\W+",
        minTokenLength=3,
    )
    df_tokens = tokenizer.transform(df_text)

    # Combine standard English stopwords with cybersecurity/domain-specific noise words.
    default_stopwords = StopWordsRemover.loadDefaultStopWords("english")
    all_stopwords = list(set(default_stopwords + DEFAULT_STOPWORDS))

    remover = StopWordsRemover(
        inputCol="words",
        outputCol="filtered_words",
        stopWords=all_stopwords,
    )
    df_clean = remover.transform(df_tokens)

    vectorizer = CountVectorizer(
        inputCol="filtered_words",
        outputCol="raw_features",
        vocabSize=vocab_size,
        minDF=min_df,
    )
    cv_model = vectorizer.fit(df_clean)
    df_vectorized = cv_model.transform(df_clean)

    idf = IDF(
        inputCol="raw_features",
        outputCol="tfidf_features",
    )
    idf_model = idf.fit(df_vectorized)
    df_tfidf = idf_model.transform(df_vectorized)

    print(f"Vocabulary size: {len(cv_model.vocabulary)}")
    return df_tfidf, cv_model, idf_model


def apply_pca(df_tfidf: DataFrame, vocab_size: int, pca_components: int = 50) -> Tuple[DataFrame, PCA]:
    """Reduce TF-IDF dimensionality using PCA."""
    pca_k = min(pca_components, vocab_size)
    print(f"Training PCA with k={pca_k}")

    pca = PCA(
        k=pca_k,
        inputCol="tfidf_features",
        outputCol="features",
    )
    pca_model = pca.fit(df_tfidf)
    df_pca = pca_model.transform(df_tfidf)

    explained_variance = pca_model.explainedVariance.toArray()
    print("PCA first components explained variance:", explained_variance[:10])
    print("PCA total explained variance:", explained_variance.sum())

    return df_pca, pca_model


def evaluate_k_values(df_pca: DataFrame, k_values: List[int]) -> List[Tuple[int, float, float]]:
    """Evaluate candidate K values using silhouette score and training cost."""
    evaluator = ClusteringEvaluator(
        featuresCol="features",
        predictionCol="prediction",
        metricName="silhouette",
    )

    results = []

    for k in k_values:
        kmeans = KMeans(
            featuresCol="features",
            predictionCol="prediction",
            k=k,
            seed=42,
            maxIter=20,
        )

        model = kmeans.fit(df_pca)
        predictions = model.transform(df_pca)

        silhouette = evaluator.evaluate(predictions)
        cost = model.summary.trainingCost

        results.append((k, silhouette, cost))
        print(f"K={k} | Silhouette={silhouette:.4f} | Cost={cost:.2f}")

    return results


def train_final_kmeans(df_pca: DataFrame, best_k: int) -> DataFrame:
    """Train the final KMeans model using the selected K."""
    print(f"Training final KMeans model with K={best_k}")

    kmeans = KMeans(
        featuresCol="features",
        predictionCol="cluster_id",
        k=best_k,
        seed=42,
        maxIter=20,
    )

    model = kmeans.fit(df_pca)
    return model.transform(df_pca)


def save_outputs(
    spark: SparkSession,
    full_df: DataFrame,
    clustered_text: DataFrame,
    metrics: List[Tuple[int, float, float]],
    output_path: str,
    metrics_path: str,
) -> None:
    """Save clustered vulnerabilities and clustering metrics."""
    clustered_ids = clustered_text.select("cve_id", "cluster_id")

    clustered_df = full_df.join(clustered_ids, on="cve_id", how="left")

    print(f"Writing clustered vulnerabilities to: {output_path}")
    clustered_df.write.mode("overwrite").parquet(output_path)

    print(f"Writing clustering metrics to: {metrics_path}")
    metrics_df = spark.createDataFrame(metrics, ["k", "silhouette", "cost"])
    metrics_df.write.mode("overwrite").parquet(metrics_path)

    print("Cluster sizes:")
    clustered_df.groupBy("cluster_id").count().orderBy("cluster_id").show()

    print("Average priority score per cluster:")
    clustered_df.groupBy("cluster_id").agg(
        avg("priority_score").alias("avg_priority_score")).show()

    print("KEV count per cluster:")
    clustered_df.groupBy("cluster_id").agg(
        spark_sum("is_kev").alias("kev_count")).show()


def run_clustering(
    input_path: str,
    output_path: str,
    metrics_path: str,
    k_values: List[int],
    description_length: int,
    vocab_size: int,
    min_df: int,
    pca_components: int,
) -> None:
    """Run the full clustering pipeline."""
    spark = create_spark_session()

    full_df = load_scored_vulnerabilities(spark, input_path)
    df_text = prepare_text_dataset(full_df, description_length)
    df_tfidf, cv_model, _ = build_text_features(df_text, vocab_size, min_df)
    df_pca, _ = apply_pca(df_tfidf, len(cv_model.vocabulary), pca_components)

    metrics = evaluate_k_values(df_pca, k_values)
    best_k, best_silhouette, best_cost = max(metrics, key=lambda x: x[1])

    print(f"Best K selected: {best_k}")
    print(f"Best silhouette: {best_silhouette:.4f}")
    print(f"Best cost: {best_cost:.2f}")

    clustered_text = train_final_kmeans(df_pca, best_k)

    save_outputs(
        spark=spark,
        full_df=full_df,
        clustered_text=clustered_text,
        metrics=metrics,
        output_path=output_path,
        metrics_path=metrics_path,
    )

    print("Clustering job completed.")
    spark.stop()


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Run vulnerability clustering job.")
    parser.add_argument(
        "--input-path", default="data/prod/gold/vulnerability_scores")
    parser.add_argument(
        "--output-path", default="data/prod/gold/vulnerabilities_clustered")
    parser.add_argument(
        "--metrics-path", default="data/prod/gold/clustering_metrics")
    parser.add_argument("--k-values", nargs="+", type=int,
                        default=[4, 6, 8, 10, 12])
    parser.add_argument("--description-length", type=int, default=1000)
    parser.add_argument("--vocab-size", type=int, default=2000)
    parser.add_argument("--min-df", type=int, default=20)
    parser.add_argument("--pca-components", type=int, default=50)
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    print("Starting clustering job...")
    print("Loading vulnerability scores...")

    run_clustering(
        input_path=args.input_path,
        output_path=args.output_path,
        metrics_path=args.metrics_path,
        k_values=args.k_values,
        description_length=args.description_length,
        vocab_size=args.vocab_size,
        min_df=args.min_df,
        pca_components=args.pca_components,
    )
