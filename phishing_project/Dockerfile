FROM python:3.10-slim

WORKDIR /app

ENV PIP_DEFAULT_TIMEOUT=2000
ENV PIP_RETRIES=30
ENV PIP_DISABLE_PIP_VERSION_CHECK=1

COPY requirements_docker.txt .

RUN pip install --no-cache-dir --prefer-binary -r requirements_docker.txt

COPY . .

EXPOSE 8501

CMD ["python", "-m", "streamlit", "run", "streamlit_app.py", "--server.address=0.0.0.0"]