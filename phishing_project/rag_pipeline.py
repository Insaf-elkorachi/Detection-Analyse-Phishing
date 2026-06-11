from llm_loader import generator
from prompt_builder import build_context, build_prompt
from url_analyzer import extract_urls, analyze_url
from suspicious_detector import (
    detect_suspicious_elements,
    detect_attack_type
)


def clean_output(response, prompt):
    return response.replace(prompt, "").strip()


def parse_llm_response(response):

    parsed = {
        "classification": "",
        "risk_level": "",
        "attack_type": "",
        "suspicious_elements": "",
        "explanation": "",
        "recommendations": ""
    }

    current_key = None

    mapping = {
        "Classification:": "classification",
        "Risk level:": "risk_level",
        "Risk Level:": "risk_level",
        "Attack type:": "attack_type",
        "Attack Type:": "attack_type",
        "Suspicious elements:": "suspicious_elements",
        "Suspicious Elements:": "suspicious_elements",
        "Explanation:": "explanation",
        "Recommendations:": "recommendations"
    }

    for line in response.splitlines():

        line = line.strip()

        for title, key in mapping.items():

            if line.startswith(title):
                current_key = key
                parsed[key] = line.replace(
                    title,
                    ""
                ).strip()
                break

        else:
            if current_key and line:
                parsed[current_key] += "\n" + line

    return parsed


def phishing_pipeline(user_message, retrieved_docs):

    print("Building RAG context...")
    context = build_context(retrieved_docs)

    print("Detecting suspicious elements...")
    detected_elements = detect_suspicious_elements(
        user_message
    )

    print("Detecting attack type...")
    detected_attack_type = detect_attack_type(
        user_message
    )

    print("\nDetected suspicious elements:")
    print(detected_elements)

    print("\nDetected attack type:")
    print(detected_attack_type)

    print("\nBuilding enriched prompt...")
    prompt = build_prompt(
        user_message,
        context
    )

    print("Generating LLM response...")

    raw_response = generator(
        prompt
    )[0]["generated_text"]

    final_response = clean_output(
        raw_response,
        prompt
    )

    print("\nRAW LLM OUTPUT:")
    print(final_response)
    print("\n")

    print("Analyzing URLs...")

    urls = extract_urls(
        user_message
    )

    url_results = []

    for url in urls:

        url_results.append({
            "url": url,
            "analysis": analyze_url(url)
        })

    parsed_response = parse_llm_response(
        final_response
    )

    return {

        "input_message": user_message,

        "classification":
            parsed_response["classification"],

        "risk_level":
            parsed_response["risk_level"],

        "attack_type":
            parsed_response["attack_type"],

        "detected_attack_type":
            detected_attack_type,

        "suspicious_elements":
            parsed_response["suspicious_elements"],

        "detected_elements":
            detected_elements,

        "explanation":
            parsed_response["explanation"],

        "recommendations":
            parsed_response["recommendations"],

        "url_analysis":
            url_results,

        "response":
            final_response,

        "raw_response":
            final_response,

        "retrieved_documents":
            retrieved_docs,

        "urls":
            url_results
    }
