import re


def extract_urls(text):
    return re.findall(
        r"https?://\S+|www\.\S+",
        text
    )


def analyze_url(url):

    suspicious_words = [
        "login",
        "verify",
        "bank",
        "gift",
        "free",
        "secure",
        "update",
        "confirm",
        "account",
        "password",
        "wallet",
        "bonus"
    ]

    score = 0
    reasons = []

    if "http://" in url:
        score += 25
        reasons.append("Uses HTTP instead of HTTPS")

    for word in suspicious_words:
        if word in url.lower():
            score += 10
            reasons.append(f"Contains suspicious keyword: {word}")

    if len(url) > 60:
        score += 10
        reasons.append("Very long URL")

    score = min(score, 100)

    if score >= 80:
        risk_level = "Critical"
    elif score >= 60:
        risk_level = "High"
    elif score >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "url": url,
        "risk_score": score,
        "risk_level": risk_level,
        "reasons": reasons
    }