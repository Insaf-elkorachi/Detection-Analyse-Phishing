from fastapi import FastAPI
from pydantic import BaseModel
from dashboard_api import analyze_message

app = FastAPI(
    title="Phishing Detection API",
    description="API pour analyser les messages suspects avec RAG",
    version="1.0"
)


class MessageRequest(BaseModel):
    message: str


@app.get("/")
def home():
    return {
        "status": "running",
        "message": "Phishing Detection API is ready"
    }


@app.post("/analyze")
def analyze(request: MessageRequest):
    result = analyze_message(request.message)
    return result