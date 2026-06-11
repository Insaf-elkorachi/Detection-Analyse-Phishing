from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

from retrieval import retrieve_similar
from rag_pipeline import phishing_pipeline


test_data = [
    {
        "message": "Your bank account has been suspended. Click here immediately: http://bank-login-free.com",
        "true_label": "phishing"
    },
    {
        "message": "Votre compte bancaire est bloqué. Vérifiez votre mot de passe ici: http://secure-bank-login.com",
        "true_label": "phishing"
    },
    {
        "message": "La réunion est prévue demain à 10h dans la salle B12.",
        "true_label": "legitimate"
    },
    {
        "message": "Your package delivery failed. Click here to confirm your address: http://delivery-check.com",
        "true_label": "phishing"
    },
    {
        "message": "Bonjour, voici le compte rendu de la réunion d'hier.",
        "true_label": "legitimate"
    }
]


def normalize_label(text):
    text = str(text).lower().strip()

    phishing_patterns = [
        "classification: phishing",
        "**classification:** phishing",
        "### classification: phishing",
        "appears to be **phishing**",
        "appears to be phishing",
        "classified as phishing",
        "this is phishing",
        "this appears to be phishing",
        "phishing attempt"
    ]

    legitimate_patterns = [
        "classification: legitimate",
        "**classification:** legitimate",
        "### classification: legitimate",
        "appears to be **legitimate**",
        "appears to be legitimate",
        "classified as legitimate",
        "this is legitimate",
        "this appears to be legitimate",
        "risk level: low",
        "attack type: normal",
        "no suspicious elements",
        "none identified"
    ]

    for pattern in legitimate_patterns:
        if pattern in text:
            return "legitimate"

    for pattern in phishing_patterns:
        if pattern in text:
            return "phishing"

    return "unknown"

true_labels = []
predicted_labels = []


for item in test_data:

    message = item["message"]
    true_label = item["true_label"]

    print("\n" + "=" * 80)
    print("MESSAGE")
    print("=" * 80)
    print(message)

    retrieved_docs = retrieve_similar(
        message,
        top_k=3
    )

    result = phishing_pipeline(
        user_message=message,
        retrieved_docs=retrieved_docs
    )

    prediction_text = (
        result.get("classification", "")
        + "\n"
        + result.get("raw_response", "")
        + "\n"
        + result.get("response", "")
    )

    predicted_label = normalize_label(prediction_text)

    if predicted_label == "unknown":
        detected_elements = result.get("detected_elements", [])
        url_analysis = result.get("url_analysis", [])

        if detected_elements or url_analysis:
            predicted_label = "phishing"
        else:
            predicted_label = "legitimate"

    print("\nTrue label      :", true_label)
    print("Predicted label :", predicted_label)

    true_labels.append(true_label)
    predicted_labels.append(predicted_label)


accuracy = accuracy_score(
    true_labels,
    predicted_labels
)

precision = precision_score(
    true_labels,
    predicted_labels,
    average="macro",
    zero_division=0
)

recall = recall_score(
    true_labels,
    predicted_labels,
    average="macro",
    zero_division=0
)

f1 = f1_score(
    true_labels,
    predicted_labels,
    average="macro",
    zero_division=0
)


print("\n" + "=" * 80)
print("LLM EVALUATION RESULTS")
print("=" * 80)

print("True labels      :", true_labels)
print("Predicted labels :", predicted_labels)
print(f"Accuracy         : {accuracy:.3f}")
print(f"Precision        : {precision:.3f}")
print(f"Recall           : {recall:.3f}")
print(f"F1-score         : {f1:.3f}")