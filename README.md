# HermesSec — Open-Source AI Security Micro-Audit Agent

Built for the **Hacktoberfest 2026 Open-Source AI Challenge (Week 2: Side Hustle)**.

HermesSec helps freelance penetration testers and application security consultants productize a **$149 Express Pre-Launch Code Audit** side hustle using **Google Gemma** open-weight models, **Backboard** unified model routing & persistent thread memory (`POST https://app.backboard.io/api/threads/messages`), and **Render** Docker hosting.

## Features
- **Sub-Agent 1 (Deterministic Python AST & Regex Triage)**: Pinpoints exact line numbers for dangerous sinks (`CWE-89`, `CWE-78`, `CWE-79`, `CWE-94`, `CWE-502`, `CWE-798`).
- **Sub-Agent 2 (Google Gemma Open-Weight Remediation Engine)**: Synthesizes drop-in secure patches and executive summaries via Backboard or local Ollama (`gemma2:9b`).
- **Sub-Agent 3 (Backboard Stateful Memory & Benchmark Router)**: Compares `google/gemma-2-9b-it` against `qwen-2.5-coder-7b-instruct` using a single API key with `memory="Auto"`.

## Quickstart (Local or Render)

```bash
pip install -r requirements.txt
export BACKBOARD_API_KEY="your_key" # Optional: falls back to local Ollama or AST engine
uvicorn app:app --reload --port 10000
```

## License
MIT License — Open-Source for Hacktoberfest 2026.
