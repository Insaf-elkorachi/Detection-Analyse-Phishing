def detect_suspicious_elements(text):

    text = text.lower()

    suspicious = []

    urgency_words = [
        "urgent",
        "immediately",
        "suspended",
        "verify",
        "click here",
        "act now",
        "limited time",
        "bloqué",
        "suspendu",
        "immédiatement",
        "vérifiez",
        "اضغط",
        "فورا",
        "تم إيقاف"
    ]

    phishing_keywords = [
        "password",
        "bank",
        "account",
        "login",
        "verification",
        "mot de passe",
        "banque",
        "compte",
        "حساب",
        "بنك"
    ]

    for word in urgency_words:
        if word in text:
            suspicious.append("Urgency")

    for word in phishing_keywords:
        if word in text:
            suspicious.append("Sensitive Information Request")

    if (
        "http://" in text
        or "https://" in text
        or "www." in text
    ):
        suspicious.append("Suspicious URL")

    return list(set(suspicious))


def detect_attack_type(text):

    text = text.lower()

    if (
        "bank" in text
        or "account" in text
        or "banque" in text
        or "compte" in text
        or "بنك" in text
        or "حساب" in text
    ):
        return "Banking Fraud"

    if (
        "delivery" in text
        or "package" in text
        or "colis" in text
        or "livraison" in text
    ):
        return "Delivery Scam"

    if (
        "facebook" in text
        or "instagram" in text
        or "whatsapp" in text
    ):
        return "Social Media Scam"

    if (
        "password" in text
        or "login" in text
        or "mot de passe" in text
    ):
        return "Credential Theft"

    if (
        "bitcoin" in text
        or "crypto" in text
        or "wallet" in text
    ):
        return "Crypto Scam"

    return "Normal"