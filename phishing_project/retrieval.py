import re
from pathlib import Path

import numpy as np
import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from rank_bm25 import BM25Okapi


BASE_DIR = Path(__file__).resolve().parent
DATASET_CANDIDATES = [
    BASE_DIR / "dataset.csv",
    BASE_DIR / "dataset" / "dataset.csv",
    BASE_DIR.parent / "dataset.csv",
]
DATASET_PATH = next((path for path in DATASET_CANDIDATES if path.exists()), None)

if DATASET_PATH is None:
    searched = "\n".join(f"- {path}" for path in DATASET_CANDIDATES)
    raise FileNotFoundError(
        "Le fichier dataset.csv est introuvable. Emplacements vérifiés :\n"
        f"{searched}"
    )

df = pd.read_csv(DATASET_PATH)

required_columns = ["text", "label"]

for col in required_columns:
    if col not in df.columns:
        raise ValueError(f"Column '{col}' is missing from dataset.csv")

documents = df["text"].astype(str).tolist()
labels = df["label"].astype(str).tolist()

risk_levels = (
    df["risk_level"].astype(str).tolist()
    if "risk_level" in df.columns
    else ["unknown"] * len(df)
)

attack_types = (
    df["attack_type"].astype(str).tolist()
    if "attack_type" in df.columns
    else ["unknown"] * len(df)
)


stop_words_en = set([
    "the", "a", "an", "and", "or", "to", "of", "in", "on", "for",
    "is", "are", "was", "were", "be", "been", "this", "that",
    "your", "you", "we", "our", "with", "from", "by", "at"
])

stop_words_fr = set([
    "le", "la", "les", "un", "une", "des", "et", "ou", "de", "du",
    "dans", "sur", "pour", "est", "sont", "ce", "cette", "ces",
    "votre", "vous", "nous", "avec", "par", "à", "au", "aux"
])

stop_words_ar = set([
    "في", "من", "على", "إلى", "عن", "مع", "هذا", "هذه",
    "التي", "الذي", "كان", "كانت", "أن", "لا", "ما", "لم"
])

stop_words = stop_words_en.union(stop_words_fr).union(stop_words_ar)


def preprocess_text(text):
    text = str(text).lower()
    text = re.sub(r"[^a-zA-ZÀ-ÿ\u0600-\u06FF\s]", " ", text)
    tokens = text.split()
    tokens = [
        word for word in tokens
        if word not in stop_words and len(word) > 1
    ]
    return " ".join(tokens)


processed_docs = [preprocess_text(doc) for doc in documents]


# TF-IDF vectorizer
vectorizer = TfidfVectorizer()
tfidf_matrix = vectorizer.fit_transform(processed_docs)


# BM25
tokenized_docs = [doc.split() for doc in processed_docs]
bm25 = BM25Okapi(tokenized_docs)


def tfidf_search(query_text, k=5):
    processed_query = preprocess_text(query_text)
    query_vector = vectorizer.transform([processed_query])

    similarities = cosine_similarity(query_vector, tfidf_matrix)[0]
    top_indices = np.argsort(similarities)[::-1][:k]

    results = []

    for idx in top_indices:
        results.append({
            "index": int(idx),
            "text": documents[idx],
            "label": labels[idx],
            "risk_level": risk_levels[idx],
            "attack_type": attack_types[idx],
            "distance": round(float(1 - similarities[idx]), 4),
            "similarity_score": round(float(similarities[idx]), 4)
        })

    return results


def bm25_search(query_text, k=5):
    processed_query = preprocess_text(query_text)
    tokenized_query = processed_query.split()

    scores = bm25.get_scores(tokenized_query)
    top_indices = np.argsort(scores)[::-1][:k]

    results = []

    for idx in top_indices:
        results.append({
            "index": int(idx),
            "text": documents[idx],
            "label": labels[idx],
            "risk_level": risk_levels[idx],
            "attack_type": attack_types[idx],
            "bm25_score": round(float(scores[idx]), 4)
        })

    return results


def hybrid_search(query_text, k=5, alpha=0.5):
    processed_query = preprocess_text(query_text)

    query_vector = vectorizer.transform([processed_query])
    tfidf_scores = cosine_similarity(query_vector, tfidf_matrix)[0]

    tokenized_query = processed_query.split()
    bm25_scores = bm25.get_scores(tokenized_query)

    def normalize(arr):
        arr = np.array(arr)
        min_value = arr.min()
        max_value = arr.max()
        return (arr - min_value) / (max_value - min_value + 1e-9)

    tfidf_norm = normalize(tfidf_scores)
    bm25_norm = normalize(bm25_scores)

    hybrid_scores = alpha * tfidf_norm + (1 - alpha) * bm25_norm

    top_indices = np.argsort(hybrid_scores)[::-1][:k]

    results = []

    for idx in top_indices:
        results.append({
            "index": int(idx),
            "text": documents[idx],
            "label": labels[idx],
            "risk_level": risk_levels[idx],
            "attack_type": attack_types[idx],
            "distance": round(float(1 - tfidf_scores[idx]), 4),
            "hybrid_score": round(float(hybrid_scores[idx]), 4),
            "tfidf_score": round(float(tfidf_norm[idx]), 4),
            "bm25_score": round(float(bm25_norm[idx]), 4)
        })

    return results


def retrieve_similar(query_text, top_k=3):
    return hybrid_search(query_text, k=top_k, alpha=0.5)


def phishing_retrieval_pipeline(query_text, k=5, method="hybrid", alpha=0.5):
    if method == "tfidf":
        return tfidf_search(query_text, k)
    elif method == "bm25":
        return bm25_search(query_text, k)
    else:
        return hybrid_search(query_text, k, alpha)
