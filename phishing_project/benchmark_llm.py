from transformers import AutoTokenizer
from transformers import AutoModelForCausalLM
from transformers import pipeline
import time

AVAILABLE_MODELS = {
    "qwen": "Qwen/Qwen2.5-1.5B-Instruct",
    "llama": "TinyLlama/TinyLlama-1.1B-Chat-v1.0",
    "gpt2": "gpt2"
}

TEST_MESSAGE = """
Your bank account has been suspended.
Click immediately here:
http://bank-login-free.com
"""

PROMPT = f"""
You are a phishing detection assistant.

Analyze this message:
{TEST_MESSAGE}

Return ONLY this format:

Classification: phishing or legitimate
Risk level: low / medium / high / critical
Attack type: banking fraud / delivery scam / social media scam / credential theft / none
Explanation: short explanation
"""
print("=" * 80)
print("LLM BENCHMARK")
print("=" * 80)

results = []

for model_name, model_path in AVAILABLE_MODELS.items():

    print(f"\nLoading {model_name} ...")

    start = time.time()

    tokenizer = AutoTokenizer.from_pretrained(model_path)

    model = AutoModelForCausalLM.from_pretrained(
        model_path,
        device_map="cpu",
        torch_dtype="auto"
    )

    generator = pipeline(
        "text-generation",
        model=model,
        tokenizer=tokenizer,
        max_new_tokens=150,
        do_sample=False,
        return_full_text=False,
        pad_token_id=tokenizer.eos_token_id
    )

    loading_time = time.time() - start

    print("Generating answer...")

    start_generation = time.time()

    output = generator(PROMPT)[0]["generated_text"]

    generation_time = time.time() - start_generation

    results.append({
        "model": model_name,
        "loading_time": round(loading_time, 2),
        "generation_time": round(generation_time, 2)
    })

    print("\nOutput:")
    print(output)

    print("\nLoading time:", round(loading_time, 2), "sec")
    print("Generation time:", round(generation_time, 2), "sec")