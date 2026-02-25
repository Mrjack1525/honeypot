FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY honeypot ./honeypot
COPY README.md ./README.md

RUN useradd -m -u 10001 honeypot && mkdir -p /app/logs && chown -R honeypot:honeypot /app
USER honeypot

EXPOSE 8080

ENV HONEYPOT_HOST=0.0.0.0 \
    HONEYPOT_PORT=8080 \
    HONEYPOT_LOG_FILE=logs/honeypot_events.jsonl \
    LLAMA_API_URL=http://ollama:11434/api/generate \
    LLAMA_MODEL=llama3.1 \
    LLAMA_TIMEOUT=5

CMD ["python", "-m", "honeypot.server"]
