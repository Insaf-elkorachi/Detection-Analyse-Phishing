from retrieval import retrieve_similar
from rag_pipeline import phishing_pipeline

def analyze_message(user_message):
    retrieved_docs = retrieve_similar(user_message, top_k=3)

    result = phishing_pipeline(
        user_message=user_message,
        retrieved_docs=retrieved_docs
    )

    return result