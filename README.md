# Automated Phishing & Social Engineering Incident Response Playbook

## Architecture
A local-first Flask application stores investigations in SQLite. The pipeline is: parse email -> extract indicators -> run transparent rules -> optionally call Ollama -> calculate evidence-based risk -> optionally scan an attachment with trusted YARA rules -> persist audit events -> render a defanged HTML report. Optional Cuckoo, Cortex, and TheHive adapters are isolated and disabled unless configured.

## Structure
`app.py` routes and persistence; `services/` analysis and integration adapters; `templates/` HTML views; `static/` styling; `database/schema.sql` schema; `tests/` unit and route tests.

## Run on Linux/macOS
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python app.py
```
Open http://127.0.0.1:5000.

## Run on Windows PowerShell
```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python app.py
```

## Tests
`pytest -q` runs without Ollama, YARA, Cuckoo, Cortex, or TheHive.

## Optional setup
Install Ollama, run `ollama pull llama3.2`, and set `OLLAMA_BASE_URL` and `OLLAMA_MODEL`. Install `yara-python` and place trusted rules in `rules.yar`. Configure Cuckoo/Cortex/TheHive URLs and API keys only in `.env`; the app never exposes them in the UI.

## Safety and limitations
The app never executes attachments, visits URLs, submits credentials, or performs disruptive response actions. URL display is defanged in reports. A rule match, YARA match, or AI result is an investigation aid rather than proof of maliciousness. Add authentication and HTTPS before any non-local deployment. Review retention and remove sensitive records according to your organization’s policy. Use only for authorized defensive analysis.

## Feature checklist
- Implemented/tested: local dashboard, email/.eml submission, parser, indicator extraction, rule checks, transparent scoring, SQLite persistence, audit events, safe report generation, validation, optional integration status.
- Optional/configurable: Ollama/LangChain-compatible local analysis, YARA, Cuckoo, Cortex, TheHive.
- Not configured by default: authentication, external integrations, trusted YARA rules, production deployment.
