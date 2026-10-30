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
export HERMES_API_TOKEN="change-me" # Recommended outside local development
export HERMES_ALLOWED_ORIGINS="https://audit.example.com"
uvicorn app:app --reload --port 10000
```

### Enterprise safeguards

- `/api/audit` enforces Pydantic input bounds, request rate limiting, optional Bearer authentication, request IDs, security headers, and a health endpoint at `/healthz`.
- Remote memory is disabled by default. Set `HERMES_ENABLE_REMOTE_MEMORY=true` only after reviewing the provider's retention policy and tenant isolation requirements.
- Client supplied `thread_id` values are ignored by default. Enable them only in an authenticated, tenant-aware deployment with `HERMES_ALLOW_CLIENT_THREAD=true`.
- Findings are rendered with DOM `textContent`; source snippets are shortened and likely credentials are redacted before returning them.
- The automated result is a pre-audit signal. Production use should add language-specific SAST (for example Semgrep/Bandit), human review, and an approved data-handling policy.
- If the operator installs Semgrep and sets `HERMES_ENABLE_SEMGREP=true`, the API adds optional Semgrep findings. Every response also includes a SARIF 2.1.0 document for code-scanning pipelines.

Run the regression suite with:

```bash
pytest -q
```

## License
MIT License — Open-Source for Hacktoberfest 2026.
