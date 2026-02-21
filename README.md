# AI-Enhanced Honeypot (PLIX-POB + LLaMA)

This repository contains a lightweight Python honeypot that uses a **PLIX-POB** workflow and optional **LLaMA AI** enrichment to classify suspicious behavior.

## What is PLIX-POB?

PLIX-POB is modeled here as a six-phase response loop:

1. **P**robe - capture incoming request details.
2. **L**og - persist normalized events.
3. **I**nspect - evaluate immediate indicators.
4. e**X**plain - enrich events with AI context (LLaMA).
5. **P**rioritize - assign threat score / severity.
6. **O**rchestrate **B**lock - provide actionable response metadata.

## Features

- Fake endpoint surface (`/admin`, `/wp-login.php`, etc.) designed to attract scans.
- Structured JSON event logging.
- AI classification through a local LLaMA-compatible endpoint (defaults to Ollama).
- Deterministic fallback classification when LLaMA is unavailable.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m honeypot.server
```

The honeypot listens on `0.0.0.0:8080` by default.

## LLaMA integration

Set environment variables if you run a local Ollama instance:

- `LLAMA_API_URL` (default: `http://localhost:11434/api/generate`)
- `LLAMA_MODEL` (default: `llama3.1`)
- `LLAMA_TIMEOUT` (default: `5` seconds)

When the AI endpoint is unreachable, the server still runs and uses local heuristic scoring.

## Run tests

```bash
python -m unittest discover -s tests -p 'test_*.py'
```
