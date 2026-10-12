# Automated Phishing & Social Engineering Incident Response Playbook

## Architecture
A local-first Flask application stores investigations in SQLite. The pipeline is: parse email -> extract indicators -> run transparent rules -> call a configured local Ollama model through LangChain structured output -> validate the advisory with Pydantic -> calculate evidence-based risk -> optionally scan an attachment with trusted YARA rules -> persist audit events -> render a defanged HTML report. If LangChain or Ollama is unavailable, a safe HTTP fallback or unavailable status preserves the rule-based results.

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

## Enable local Ollama analysis
Install and start Ollama, confirm the service is reachable, then install a local model:

```bash
ollama serve
ollama list
ollama pull llama3.2
```

Set the model in `.env` to the exact name shown by `ollama list`:

```dotenv
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_MODEL=llama3.2
OLLAMA_TIMEOUT_SECONDS=30
OLLAMA_NUM_PREDICT=800
```

The application first uses `langchain-ollama` with a Pydantic structured-output schema. If that adapter is unavailable, it uses Ollama’s local `/api/chat` endpoint with JSON mode and validates the response with the same schema. The model receives email content as untrusted evidence and must not be allowed to follow instructions embedded in messages.

For the public managed deployment, `127.0.0.1` refers to the published container, not this sandbox or a personal computer. A host-local Ollama service is therefore available to local runs only; a public deployment needs an explicitly configured reachable Ollama endpoint and appropriate network controls. Never expose Ollama or model credentials publicly.

## Tests
`pytest -q` runs without Ollama, YARA, Cuckoo, Cortex, or TheHive. Tests use safe fallback behavior and schema validation rather than a live model.

## Optional setup
Install `yara-python` and place trusted rules in `rules.yar`. Configure Cuckoo/Cortex/TheHive URLs and API keys only in `.env`; the app never exposes them in the UI.

## Safety and limitations
The app never executes attachments, visits URLs, submits credentials, or performs disruptive response actions. URL display is defanged in reports. A rule match, YARA match, or AI result is an investigation aid rather than proof of maliciousness. Add authentication and HTTPS before any non-local deployment. Review retention and remove sensitive records according to your organization’s policy. Use only for authorized defensive analysis.

## Feature checklist
- Implemented/tested: local dashboard, email/.eml submission, parser, indicator extraction, rule checks, transparent scoring, SQLite persistence, audit events, safe report generation, validation, responsive mobile navigation, and Ollama/LangChain structured-output integration with safe fallback.
- Optional/configurable: local Ollama model, YARA, Cuckoo, Cortex, TheHive.
- Not configured by default: authentication, external integrations, trusted YARA rules, and a publicly reachable Ollama endpoint.
