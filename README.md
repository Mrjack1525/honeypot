# AI-Enhanced Honeypot System (PLIX-POB + LLaMA)

This project provides a container-ready honeypot system that captures hostile HTTP traffic and classifies it using a **PLIX-POB** workflow with optional **LLaMA** enrichment.

## PLIX-POB workflow

1. **Probe**: capture client, path, query, method, and user-agent.
2. **Log**: persist normalized event objects in JSONL.
3. **Inspect**: apply deterministic IOC checks (path, traversal, scanner UAs).
4. **eXplain**: enrich event with LLaMA SOC-style reasoning when available.
5. **Prioritize**: convert severity into a risk score.
6. **Orchestrate Block**: emit response metadata for temporary blocking.

## System layout

- `honeypot/plix_pob.py` — core engine, heuristic + LLaMA analyzer.
- `honeypot/server.py` — HTTP decoy server (`/health` + trap behavior).
- `docker-compose.yml` — full deployment with honeypot + Ollama.
- `Dockerfile` — production-like image for the honeypot service.

## Local run (without Docker)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m honeypot.server
```

Server defaults to `0.0.0.0:8080` and writes logs to `logs/honeypot_events.jsonl`.

## Deploy with Docker (recommended)

```bash
docker compose up --build -d
```

Then validate:

```bash
curl -i http://localhost:8080/health
curl -i -A "sqlmap/1.7" http://localhost:8080/wp-login.php
```

Logs are persisted to `./logs/honeypot_events.jsonl` on the host.

## LLaMA/Ollama configuration

Environment variables:

- `LLAMA_API_URL` (default `http://ollama:11434/api/generate`)
- `LLAMA_MODEL` (default `llama3.1`)
- `LLAMA_TIMEOUT` (default `5`)
- `HONEYPOT_HOST` (default `0.0.0.0`)
- `HONEYPOT_PORT` (default `8080`)
- `HONEYPOT_LOG_FILE` (default `logs/honeypot_events.jsonl`)

If LLaMA is unavailable, the engine automatically falls back to heuristic scoring.

## Tests

```bash
python -m unittest discover -s tests -p 'test_*.py'
python -m py_compile honeypot/*.py tests/*.py
```
