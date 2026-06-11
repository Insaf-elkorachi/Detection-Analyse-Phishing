import csv
import io
import ipaddress
import json
import re
import socket
from collections import Counter
from datetime import datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import pandas as pd


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_HISTORY_PATH = BASE_DIR / "results" / "analysis_history.csv"
DEFAULT_GEO_CACHE_PATH = BASE_DIR / "results" / "geo_cache.json"
DATASET_PATH = BASE_DIR / "dataset.csv"

HISTORY_COLUMNS = [
    "Date",
    "Message",
    "Classification",
    "Risque",
    "Type d'attaque",
]

RISK_WEIGHTS = {
    "low": 20,
    "faible": 20,
    "medium": 50,
    "moyen": 50,
    "high": 80,
    "élevé": 80,
    "eleve": 80,
    "critical": 100,
    "critique": 100,
}

URGENCY_TERMS = (
    "urgent",
    "immediately",
    "immédiatement",
    "immediatement",
    "suspended",
    "suspendu",
    "verify now",
    "vérifiez",
    "cliquez ici",
    "click here",
    "act now",
    "limited time",
    "bloqué",
    "bloque",
)

SENSITIVE_TERMS = (
    "password",
    "mot de passe",
    "bank",
    "banque",
    "account",
    "compte",
    "login",
    "identifiant",
    "verification",
    "vérification",
    "wallet",
    "carte bancaire",
)

SUSPICIOUS_DOMAIN_TERMS = (
    "login",
    "verify",
    "bank",
    "secure",
    "account",
    "password",
    "free",
    "bonus",
    "gift",
    "update",
    "confirm",
)


def load_history(path=DEFAULT_HISTORY_PATH):
    history_path = Path(path)
    if not history_path.exists() or history_path.stat().st_size == 0:
        history = pd.DataFrame(columns=HISTORY_COLUMNS)
        history["Date"] = pd.Series(dtype="datetime64[ns]")
        return history

    try:
        history = pd.read_csv(
            history_path,
            header=None,
            names=HISTORY_COLUMNS,
            encoding="utf-8",
            on_bad_lines="skip",
        )
    except UnicodeDecodeError:
        history = pd.read_csv(
            history_path,
            header=None,
            names=HISTORY_COLUMNS,
            encoding="latin-1",
            on_bad_lines="skip",
        )

    history["Date"] = pd.to_datetime(history["Date"], errors="coerce")
    for column in HISTORY_COLUMNS[1:]:
        history[column] = history[column].fillna("").astype(str)
    return history.dropna(subset=["Date"]).sort_values("Date", ascending=False)


def save_history(message, result, path=DEFAULT_HISTORY_PATH):
    history_path = Path(path)
    history_path.parent.mkdir(parents=True, exist_ok=True)
    with history_path.open("a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(
            [
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                message,
                result.get("classification", ""),
                result.get("risk_level", ""),
                result.get("attack_type", ""),
            ]
        )


def is_phishing(value):
    normalized = str(value).strip().lower()
    return normalized in {"phishing", "fraud", "malicious", "suspect"}


def dashboard_kpis(history, dataset=None):
    source = dataset if dataset is not None and not dataset.empty else history
    label_column = "label" if source is dataset else "Classification"

    if source.empty or label_column not in source.columns:
        return {
            "total": 0,
            "phishing": 0,
            "legitimate": 0,
            "phishing_rate": 0.0,
        }

    labels = source[label_column].fillna("").astype(str)
    total = len(labels)
    phishing = int(labels.map(is_phishing).sum())
    legitimate = max(total - phishing, 0)
    rate = (phishing / total * 100) if total else 0.0

    return {
        "total": total,
        "phishing": phishing,
        "legitimate": legitimate,
        "phishing_rate": round(rate, 1),
    }


def dataset_quality_metrics(dataset):
    if dataset is None or dataset.empty:
        return {
            "rows": 0,
            "unique_texts": 0,
            "duplicate_rate": 0.0,
            "synthetic_rate": 0.0,
            "url_label_agreement": 0.0,
        }

    rows = len(dataset)
    unique_texts = int(dataset["text"].nunique()) if "text" in dataset.columns else rows
    duplicate_rate = ((rows - unique_texts) / rows * 100) if rows else 0.0

    synthetic_rate = 0.0
    if "synthetic_generated" in dataset.columns:
        synthetic = pd.to_numeric(
            dataset["synthetic_generated"],
            errors="coerce",
        ).fillna(0)
        synthetic_rate = float((synthetic > 0).mean() * 100)

    url_label_agreement = 0.0
    if {"contains_url", "label"}.issubset(dataset.columns):
        contains_url = pd.to_numeric(
            dataset["contains_url"],
            errors="coerce",
        ).fillna(0).astype(bool)
        phishing = dataset["label"].map(is_phishing)
        url_label_agreement = float((contains_url == phishing).mean() * 100)

    return {
        "rows": rows,
        "unique_texts": unique_texts,
        "duplicate_rate": round(duplicate_rate, 1),
        "synthetic_rate": round(synthetic_rate, 1),
        "url_label_agreement": round(url_label_agreement, 1),
    }


def risk_score(value):
    normalized = str(value).strip().lower()
    for label, score in RISK_WEIGHTS.items():
        if label in normalized:
            return score
    return 0


def average_risk(history):
    if history.empty:
        return 0.0
    scores = history["Risque"].map(risk_score)
    scores = scores[scores > 0]
    return float(scores.mean()) if not scores.empty else 0.0


def confidence_score(result):
    explicit = result.get("confidence") or result.get("confidence_score")
    if explicit is not None:
        try:
            value = float(str(explicit).replace("%", ""))
            return max(0, min(value, 100))
        except ValueError:
            pass

    score = 52
    if is_phishing(result.get("classification")):
        score += 14
    score += min(len(result.get("detected_elements") or []) * 5, 15)
    url_scores = []
    for item in result.get("url_analysis") or []:
        analysis = item.get("analysis", item)
        url_scores.append(float(analysis.get("risk_score", 0)))
    if url_scores:
        score += max(url_scores) * 0.14
    if risk_score(result.get("risk_level")) >= 80:
        score += 5
    return round(max(0, min(score, 99)), 1)


def _message_reasons(message):
    text = str(message).lower()
    urls = extract_urls(text)
    reasons = []
    if urls:
        reasons.append("URL suspecte détectée")
    if any(term in text for term in URGENCY_TERMS):
        reasons.append("Mot ou formulation d'urgence détecté")
    if any(term in text for term in SENSITIVE_TERMS):
        reasons.append("Demande ou référence à des informations sensibles")
    if any(
        term in domain_from_url(url)
        for url in urls
        for term in SUSPICIOUS_DOMAIN_TERMS
    ):
        reasons.append("Nom de domaine potentiellement trompeur")
    return reasons


def _translate_reason(reason):
    translations = {
        "urgency": "Mot ou formulation d'urgence détecté",
        "sensitive information request": "Demande ou référence à des informations sensibles",
        "suspicious url": "URL suspecte détectée",
        "uses http instead of https": "Connexion HTTP non chiffrée",
        "very long url": "URL anormalement longue",
    }
    normalized = str(reason).strip()
    lower = normalized.lower()
    if lower.startswith("contains suspicious keyword:"):
        keyword = normalized.split(":", 1)[-1].strip()
        return f"Mot-clé suspect dans l'URL : {keyword}"
    return translations.get(lower, normalized)


def decision_reasons(result):
    reasons = [_translate_reason(item) for item in result.get("detected_elements") or []]
    for item in result.get("url_analysis") or []:
        analysis = item.get("analysis", item)
        reasons.extend(_translate_reason(reason) for reason in analysis.get("reasons", []))
    reasons.extend(_message_reasons(result.get("input_message", "")))
    return list(dict.fromkeys(reason for reason in reasons if reason))


def extract_urls(text):
    return re.findall(r"https?://[^\s<>'\"]+|www\.[^\s<>'\"]+", str(text))


def domain_from_url(url):
    candidate = str(url).strip().rstrip(".,;:!?)]}")
    parsed = urlparse(candidate if "://" in candidate else f"http://{candidate}")
    return parsed.netloc.lower().split("@")[-1].split(":")[0].removeprefix("www.")


def top_domains(messages, limit=10):
    counts = Counter()
    for message in messages:
        for url in extract_urls(message):
            domain = domain_from_url(url)
            if domain:
                counts[domain] += 1
    return pd.DataFrame(counts.most_common(limit), columns=["Domaine", "Occurrences"])


def _load_geo_cache(path=DEFAULT_GEO_CACHE_PATH):
    cache_path = Path(path)
    if not cache_path.exists():
        return {}
    try:
        return json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _save_geo_cache(cache, path=DEFAULT_GEO_CACHE_PATH):
    cache_path = Path(path)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(
        json.dumps(cache, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _resolve_public_ip(domain):
    try:
        addresses = socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return None

    for address in addresses:
        candidate = address[4][0]
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if ip.is_global:
            return str(ip)
    return None


def _lookup_ip_location(ip):
    request = Request(
        f"https://ipwho.is/{ip}?fields=success,country,country_code,city,latitude,longitude,connection",
        headers={"User-Agent": "PhishingDashboard/1.0"},
    )
    try:
        with urlopen(request, timeout=6) as response:
            data = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, OSError):
        return None

    if not data.get("success"):
        return None
    if data.get("latitude") is None or data.get("longitude") is None:
        return None
    connection = data.get("connection") or {}
    return {
        "IP": ip,
        "Pays": data.get("country") or "Inconnu",
        "Code pays": data.get("country_code") or "",
        "Ville": data.get("city") or "Inconnue",
        "Latitude": float(data["latitude"]),
        "Longitude": float(data["longitude"]),
        "Organisation": connection.get("org") or connection.get("isp") or "Inconnue",
    }


def geolocate_domains(messages, limit=10, refresh=False, lookup_missing=True):
    domains = top_domains(messages, limit=limit)
    if domains.empty:
        return pd.DataFrame(), 0

    cache = _load_geo_cache()
    rows = []
    failures = 0

    for item in domains.to_dict("records"):
        domain = item["Domaine"]
        location = None if refresh else cache.get(domain)

        if not location and lookup_missing:
            ip = _resolve_public_ip(domain)
            location = _lookup_ip_location(ip) if ip else None
            if location:
                cache[domain] = location

        if not location:
            failures += 1
            continue

        rows.append(
            {
                "Domaine": domain,
                "Occurrences": int(item["Occurrences"]),
                **location,
            }
        )

    _save_geo_cache(cache)
    return pd.DataFrame(rows), failures


def url_rows(result):
    url_items = result.get("url_analysis") or []
    if not url_items:
        url_items = [{"url": url} for url in extract_urls(result.get("input_message", ""))]

    rows = []
    for item in url_items:
        analysis = item.get("analysis", item)
        url = item.get("url") or analysis.get("url", "")
        domain = domain_from_url(url)
        score = int(float(analysis.get("risk_score", 0) or 0))
        if not score:
            score = 25 if str(url).lower().startswith("http://") else 10
            score += sum(10 for term in SUSPICIOUS_DOMAIN_TERMS if term in domain)
        if is_phishing(result.get("classification")):
            score = max(score, 90 if risk_score(result.get("risk_level")) >= 80 else 75)
        score = min(score, 100)
        if score >= 80:
            level = "Élevé"
        elif score >= 50:
            level = "Moyen"
        else:
            level = "Faible"
        rows.append(
            {
                "URL": url,
                "Domaine": domain,
                "HTTPS": "Oui" if str(url).lower().startswith("https://") else "Non",
                "Blacklist": "Non vérifié",
                "Âge du domaine": "Non disponible",
                "Score de risque": f"{score}%",
                "Niveau": level,
            }
        )
    return pd.DataFrame(rows)


def history_csv_bytes(history):
    export = history.copy()
    if "Date" in export:
        dates = pd.to_datetime(export["Date"], errors="coerce")
        export["Date"] = dates.dt.strftime("%Y-%m-%d %H:%M:%S").fillna("")
    return export.to_csv(index=False).encode("utf-8-sig")


def result_json_bytes(result):
    return json.dumps(result, indent=2, ensure_ascii=False).encode("utf-8")


def _pdf_escape(text):
    return (
        str(text)
        .encode("latin-1", errors="replace")
        .decode("latin-1")
        .replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
    )


def result_pdf_bytes(result):
    reasons = decision_reasons(result)
    lines = [
        "RAPPORT D'ANALYSE PHISHING",
        "",
        f"Classification : {result.get('classification', 'N/A')}",
        f"Niveau de risque : {result.get('risk_level', 'N/A')}",
        f"Type d'attaque : {result.get('attack_type', 'N/A')}",
        f"Confiance IA : {confidence_score(result)}%",
        "",
        "Raisons de la decision :",
    ]
    lines.extend(f"- {reason}" for reason in reasons[:12])
    lines.extend(["", "Message analyse :"])
    message = re.sub(r"\s+", " ", str(result.get("input_message", ""))).strip()
    lines.extend(message[index : index + 90] for index in range(0, len(message), 90))

    stream_lines = ["BT", "/F1 12 Tf", "50 790 Td"]
    for index, line in enumerate(lines[:42]):
        if index:
            stream_lines.append("0 -18 Td")
        stream_lines.append(f"({_pdf_escape(line)}) Tj")
    stream_lines.append("ET")
    stream = "\n".join(stream_lines).encode("latin-1", errors="replace")

    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        f"<< /Length {len(stream)} >>\nstream\n".encode("ascii")
        + stream
        + b"\nendstream",
    ]

    output = io.BytesIO()
    output.write(b"%PDF-1.4\n")
    offsets = [0]
    for number, obj in enumerate(objects, 1):
        offsets.append(output.tell())
        output.write(f"{number} 0 obj\n".encode("ascii"))
        output.write(obj)
        output.write(b"\nendobj\n")

    xref = output.tell()
    output.write(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    output.write(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.write(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.write(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref}\n%%EOF"
        ).encode("ascii")
    )
    return output.getvalue()
