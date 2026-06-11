# AI-Powered Phishing Detection System Using Retrieval-Augmented Generation (RAG) and Large Language Models

## Project Overview

Phishing attacks remain one of the most widespread cybersecurity threats, targeting users through emails, SMS messages, social media platforms, and malicious websites. Traditional detection approaches often rely on static rules and struggle to adapt to evolving phishing techniques.

This project presents an intelligent phishing detection platform that combines Natural Language Processing (NLP), Retrieval-Augmented Generation (RAG), semantic search, URL analysis, and Large Language Models (LLMs) to provide accurate, explainable, and interactive phishing detection.

The system analyzes suspicious messages, retrieves semantically similar examples from a knowledge base, identifies phishing indicators, evaluates URL risks, generates contextual explanations, and provides security recommendations through an interactive dashboard.

---

# Objectives

The main objectives of this project are:

* Detect phishing and legitimate messages.
* Analyze suspicious URLs.
* Identify phishing attack categories.
* Generate detailed explanations and recommendations.
* Support multilingual content (English, French, and Arabic).
* Provide an interactive cybersecurity dashboard.
* Improve explainability using Retrieval-Augmented Generation (RAG).

---

# System Architecture

```text
                    User
                      │
                      ▼
             Streamlit Dashboard
                      │
                      ▼
              Message Analysis
                      │
                      ▼
                RAG Pipeline
                      │
      ┌───────────────┴───────────────┐
      ▼                               ▼
 Semantic Retrieval             URL Analysis
 (Sentence Transformers)      Risk Scoring Engine
      │                               │
      └───────────────┬───────────────┘
                      ▼
                  FAISS Index
                      │
                      ▼
                  LLM Module
                      │
                      ▼
            Phishing Detection Result
                      │
                      ▼
Classification • Risk Level • Attack Type
Explanation • Recommendations
```

---

# Dataset

The dataset contains phishing and legitimate messages generated and collected for phishing detection experiments.

### Dataset Statistics

* Total Messages: 500
* Phishing Messages: 288
* Legitimate Messages: 212
* Languages: English, French, Arabic
* Attack Categories: 8

### Data Sources

* Emails
* SMS Messages
* Social Media Messages
* Suspicious URLs
* Legitimate Communications

Each record contains:

* Message Content
* Classification Label
* Risk Level
* Attack Type
* Language
* Communication Channel

---

# Retrieval System

The retrieval module enhances detection by providing contextual examples.

### Semantic Retrieval

Sentence Transformers are used to generate vector embeddings for messages.

### FAISS Indexing

FAISS is employed for efficient similarity search over vector representations.

The retrieval module returns the most relevant examples that help the language model produce contextualized and explainable decisions.

---

# Retrieval-Augmented Generation (RAG)

The RAG pipeline follows these steps:

1. User submits a message.
2. Message preprocessing.
3. Semantic retrieval of similar examples.
4. Context generation.
5. Prompt construction.
6. LLM inference.
7. Result generation.

This architecture reduces hallucinations and improves explanation quality by grounding the language model on retrieved examples.

---

# Large Language Models

Several language models were evaluated:

* Qwen2.5-1.5B-Instruct
* TinyLlama-1.1B-Chat
* GPT-2

Evaluation criteria included:

* Classification quality
* Explanation quality
* Consistency
* Inference speed
* Prompt adherence

### Selected Model

After experimentation, **Qwen2.5-1.5B-Instruct** was selected as the primary model due to its superior balance between accuracy, explanation quality, and computational efficiency.

---

# Phishing Detection Features

The platform provides:

## Classification

* Phishing
* Legitimate

## Risk Assessment

* Low
* Medium
* High
* Critical

## Attack Type Detection

* Banking Fraud
* Credential Theft
* Delivery Scam
* Crypto Scam
* Social Media Scam
* Fake Support Scam
* Job Scam
* Normal Communication

## Suspicious Element Detection

The system automatically identifies:

* Urgency indicators
* Sensitive information requests
* Suspicious URLs
* Account verification requests
* Login requests
* Password requests

---

# URL Analysis

The URL analysis module evaluates links using multiple indicators:

* Suspicious keywords
* HTTP versus HTTPS
* URL structure
* Domain characteristics
* Potential phishing indicators

Each URL receives:

* Risk Score
* Risk Level
* Detection Explanation

### Example

```text
URL: http://bank-login-free.com

Risk Score: 85/100
Risk Level: High

Reasons:
- Uses HTTP instead of HTTPS
- Contains suspicious keyword: bank
- Contains suspicious keyword: login
- Contains suspicious keyword: free
```

---

# Dashboard Features

The Streamlit dashboard provides:

* Interactive message analysis
* AI confidence score
* Risk assessment
* Attack type visualization
* URL investigation
* Explainable AI indicators
* Historical analysis tracking
* Dataset analytics
* GeoIP visualization
* PDF export
* CSV export
* JSON export

---

# Data Analytics

The dashboard includes:

### Key Performance Indicators (KPIs)

* Total Messages
* Unique Messages
* Duplicate Rate
* Attack Categories

### Visualizations

* Phishing vs Legitimate Distribution
* Language Distribution
* Communication Channel Distribution
* Risk Level Distribution
* Top Malicious Domains
* Risk Gauge
* Attack Type Distribution
* Attack Type vs Risk Heatmap
* GeoIP Visualization

---

# Technologies Used

## Programming

* Python

## Data Processing

* Pandas
* NumPy

## Natural Language Processing

* NLTK
* Sentence Transformers

## Retrieval

* FAISS

## Generative AI

* Hugging Face Transformers
* PyTorch

## Machine Learning

* Scikit-Learn

## Visualization

* Plotly
* Streamlit

## Storage

* SQLite

---

# Project Structure

```text
project/
│
├── dataset/
├── retrieval/
├── rag_pipeline/
├── url_analysis/
├── evaluation/
├── dashboard/
├── results/
├── docs/
├── report/
└── README.md
```

---

# Installation

Install the required dependencies:

```bash
pip install -r requirements.txt
```

---

# Running the Project

## Dashboard only

```powershell
cd .\phishing_project
.\.venv\Scripts\python.exe -m streamlit run streamlit_app.py
```

## API only

```powershell
cd .\phishing_project
.\.venv\Scripts\python.exe -m uvicorn backend_api:app --reload
```

---

# Example Output

```json
{
  "classification": "phishing",
  "risk_level": "high",
  "attack_type": "Banking Fraud",
  "detected_elements": [
    "Urgency",
    "Sensitive Information Request",
    "Suspicious URL"
  ],
  "risk_score": 85
}
```

---

# Advantages

* Explainable AI-based detection.
* Multilingual support.
* URL risk analysis.
* Context-aware reasoning through RAG.
* Interactive cybersecurity dashboard.
* Detailed recommendations.
* Exportable reports.
* Advanced data visualization.

---

# Limitations

* Performance depends on dataset quality.
* Domain age and blacklist verification require external services.
* GeoIP information identifies hosting locations rather than attackers.

---

# Future Improvements

* VirusTotal API integration.
* Real-time monitoring.
* Attachment analysis.
* User authentication.
* Cloud deployment.
* Continuous learning pipeline.

---

# Conclusion

This project demonstrates how Retrieval-Augmented Generation (RAG), semantic retrieval techniques, URL analysis, and Large Language Models can be combined to create an explainable phishing detection platform. The proposed solution improves phishing detection while providing transparent, interpretable, and actionable cybersecurity insights through an interactive dashboard.
