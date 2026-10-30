# HermesSec — Open-Source AI Security Micro-Audit Agent

Built for the **Hacktoberfest 2026 Open-Source AI Challenge (Week 2: Side Hustle)**.

HermesSec is an independently maintained, MIT-licensed pre-audit service for
Python application code. It combines deterministic AST/regex triage with
optional Semgrep and model-assisted remediation while keeping remote memory
disabled by default.

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
- Long-running reviews can use `POST /api/audit/jobs` and poll `GET /api/audit/jobs/{job_id}`. Jobs are tenant-scoped through `X-Tenant-ID`; submitted source code is never written to the job database.
- The included SQLite store is suitable for a single Render instance with the configured persistent disk. A multi-instance deployment should replace the repository functions with PostgreSQL/Redis before scaling horizontally.

Run the regression suite with:

```bash
pytest -q
```

The repository runs the same suite in GitHub Actions on Python 3.10, 3.11,
and 3.12. The automated result is a pre-audit signal, not a replacement for
language-specific SAST, human review, or an approved client data-handling
policy.

## Development notes

- Keep `BACKBOARD_API_KEY` and `HERMES_API_TOKEN` in the environment; never
  commit them or place them in fixtures.
- Use `HERMES_AUDIT_DB_PATH` to point SQLite at a persistent disk in hosted
  deployments. The included SQLite store is intended for a single instance.
- Run `pytest -q` before opening a pull request.

## License
MIT License — Open-Source for Hacktoberfest 2026.
