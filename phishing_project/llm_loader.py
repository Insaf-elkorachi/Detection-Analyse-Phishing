from transformers import AutoTokenizer
from transformers import AutoModelForCausalLM
from transformers import pipeline
import time

print("=" * 60)
print("MULTI-LLM RAG BENCHMARK SYSTEM")
print("=" * 60)



AVAILABLE_MODELS = {
    "qwen": "Qwen/Qwen2.5-1.5B-Instruct",
    "llama": "TinyLlama/TinyLlama-1.1B-Chat-v1.0",
    "gpt2": "gpt2"
}


SELECTED_MODEL = "qwen"

MODEL_NAME = AVAILABLE_MODELS[SELECTED_MODEL]

print(f"\nSelected model: {MODEL_NAME}")



print("\nLoading tokenizer...")

tokenizer = AutoTokenizer.from_pretrained(
    MODEL_NAME
)



print("Loading model...")

start_time = time.time()

model = AutoModelForCausalLM.from_pretrained(
    MODEL_NAME,
    device_map="cpu",
    torch_dtype="auto"
)

loading_time = time.time() - start_time



print("Building generation pipeline...")

generator = pipeline(
    task="text-generation",
    model=model,
    tokenizer=tokenizer,
    max_new_tokens=250,
    do_sample=False,
    temperature=None,
    return_full_text=False,
    pad_token_id=tokenizer.eos_token_id
)

print("\nLLM READY")
print(f"Model: {MODEL_NAME}")
print(f"Loading time: {loading_time:.2f} seconds")
