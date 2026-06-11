import sys
from bidi.algorithm import get_display
import arabic_reshaper

sys.stdout.reconfigure(encoding="utf-8")

from retrieval import retrieve_similar
from rag_pipeline import phishing_pipeline


def fix_arabic(text):
    try:
        reshaped_text = arabic_reshaper.reshape(str(text))
        return get_display(reshaped_text)
    except Exception:
        return str(text)


def is_arabic(text):
    return any("\u0600" <= c <= "\u06FF" for c in str(text))


def display_text(text):
    if is_arabic(text):
        return fix_arabic(text)
    return str(text)


def save_result_to_html(
    message,
    retrieved_docs,
    result,
    filename="result_arabic.html"
):
    html = f"""
<!DOCTYPE html>
<html lang="ar">
<head>
    <meta charset="UTF-8">
    <title>RAG Phishing Detection</title>
</head>

<body style="
font-family: Arial;
direction: rtl;
text-align: right;
background-color: #f5f5f5;
padding: 30px;
">

<h1 style="color: darkred;">
نتائج تحليل التصيد الاحتيالي
</h1>

<hr>

<h2>رسالة المستخدم</h2>

<div style="
background: white;
padding: 15px;
border-radius: 10px;
">
<pre>{message}</pre>
</div>

<hr>

<h2>الوثائق المسترجعة بواسطة FAISS</h2>

<div style="
background: white;
padding: 15px;
border-radius: 10px;
">

<pre>{retrieved_docs}</pre>

</div>

<hr>

<h2>نتيجة تحليل RAG</h2>

<div style="
background: white;
padding: 15px;
border-radius: 10px;
">

<pre>{result["response"]}</pre>

</div>

<hr>

<h2>تحليل الروابط</h2>

<div style="
background: white;
padding: 15px;
border-radius: 10px;
">

<pre>{result["urls"]}</pre>

</div>

</body>
</html>
"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)


test_messages = [
    """
Your bank account has been suspended.
Click immediately here:
http://bank-login-free.com
""",

    """
Votre compte bancaire a été suspendu.
Cliquez ici immédiatement pour le réactiver:
http://secure-bank-verification.com
""",

    """
تم إيقاف حسابك البنكي.
اضغط هنا لإعادة التفعيل:
http://bank-login-secure.com
""",

    """
La réunion est prévue demain à 10h dans la salle B12.
"""
]


for i, message in enumerate(test_messages, 1):

    print("\n" + "=" * 80)
    print(f"TEST {i}")
    print("=" * 80)

    print("\nUser message:")
    print(display_text(message))

    retrieved_docs = retrieve_similar(
        message,
        top_k=3
    )

    print("\nRetrieved documents:")

    for j, doc in enumerate(retrieved_docs, 1):

        print(f"\nDocument {j}")

        print("Text:", display_text(doc["text"]))
        print("Label:", doc["label"])
        print("Risk:", doc["risk_level"])
        print("Attack type:", doc["attack_type"])
        print("Distance:", doc["distance"])

    result = phishing_pipeline(
        user_message=message,
        retrieved_docs=retrieved_docs
    )

    print("\nFinal RAG result:")
    print(display_text(result["response"]))

    print("\nURL analysis:")
    print(result["urls"])

    save_result_to_html(
        message,
        retrieved_docs,
        result,
        filename=f"result_test_{i}.html"
    )

    print(f"\nHTML report saved: result_test_{i}.html")