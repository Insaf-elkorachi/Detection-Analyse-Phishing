def build_context(retrieved_docs):
    context = ""

    for i, doc in enumerate(retrieved_docs, 1):
        context += f"""
Example {i}:
Text: {doc.get("text", "")}
Label: {doc.get("label", "")}
Risk: {doc.get("risk_level", "")}
Attack type: {doc.get("attack_type", "")}
Similarity distance: {doc.get("distance", "")}
"""

    return context


def build_prompt(user_message, context):
    prompt = f"""
You are a cybersecurity assistant specialized in phishing detection.

Rules:
- Use ONLY the retrieved examples.
- Do not invent information.
- If the user message is in French, answer in French.
- If the user message is in Arabic, answer in Arabic.
- If the user message is in English, answer in English.
- Keep explanations concise and clear.

User message:
{user_message}

Retrieved similar examples:
{context}

Return EXACTLY in this format:

Classification: phishing or legitimate

Risk level: low / medium / high / critical

Attack type:

Suspicious elements:
- item 1
- item 2

Explanation:

Recommendations:
- recommendation 1
- recommendation 2
"""
    return prompt