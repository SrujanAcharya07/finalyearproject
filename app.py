from datetime import datetime, timezone
import json, secrets, sqlite3
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from werkzeug.utils import secure_filename
from config import Config
from services.email_parser import parse_email_input
from services.indicator_extractor import extract_indicators
from services.rule_engine import run_rules
from services.risk_scorer import score_risk
from services.llm_analyzer import analyze_with_llm
from services.yara_scanner import scan_file
from services.audit_logger import audit_event
from services.report_generator import generate_report

BASE = Path(__file__).parent

def now():
    return datetime.now(timezone.utc).isoformat()

def db():
    c = sqlite3.connect(Config.DATABASE_PATH)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    return c

def init_db():
    with db() as c:
        c.executescript((BASE / "database/schema.sql").read_text())

def integration_status():
    return {"ollama": bool(Config.OLLAMA_BASE_URL and Config.OLLAMA_MODEL), "yara": scan_file(None)["status"] != "unavailable", "cuckoo": bool(Config.CUCKOO_URL), "cortex": bool(Config.CORTEX_URL and Config.CORTEX_API_KEY), "thehive": bool(Config.THEHIVE_URL and Config.THEHIVE_API_KEY)}

def load(iid):
    with db() as c:
        row = c.execute("SELECT * FROM investigations WHERE id=?", (iid,)).fetchone()
        if not row:
            return None
        data = dict(row)
        for key in ["parsed_json", "indicators_json", "findings_json", "ai_json", "file_scan_json"]:
            try:
                data[key[:-5]] = json.loads(data.pop(key) or "null")
            except Exception:
                data[key[:-5]] = None
        data["risk"] = {"score": data["risk_score"], "level": data["risk_level"]}
        data["audit_events"] = [dict(x) for x in c.execute("SELECT * FROM audit_events WHERE investigation_id=? ORDER BY created_at DESC", (iid,)).fetchall()]
        return data

def error(msg, code=400):
    if request.is_json:
        return jsonify({"error": msg}), code
    flash(msg, "error")
    return redirect(request.referrer or url_for("dashboard"))

def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    app.config.update(test_config or {})
    Config.DATABASE_PATH = app.config["DATABASE_PATH"]
    Config.UPLOAD_FOLDER = app.config["UPLOAD_FOLDER"]
    Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)
    init_db()

    @app.get("/")
    def dashboard():
        with db() as c:
            stats = c.execute("SELECT COUNT(*) total, COALESCE(SUM(risk_level IN ('High','Critical')),0) high, COALESCE(SUM(risk_level='Medium'),0) medium, COALESCE(SUM(risk_level='Low'),0) low FROM investigations").fetchone()
            recent = c.execute("SELECT * FROM investigations ORDER BY created_at DESC LIMIT 8").fetchall()
        return render_template("dashboard.html", stats=stats, recent=recent)

    @app.get("/submit")
    def submit_page():
        return render_template("submit_email.html")

    @app.get("/settings")
    def settings():
        return render_template("settings.html", integrations=integration_status())

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "mode": "local-only capable", "timestamp": now()})

    @app.get("/manus-routes.json")
    def manus_routes():
        return jsonify({"routes": [{"path": "/", "title": "Dashboard"}, {"path": "/submit", "title": "Submit suspicious email"}, {"path": "/settings", "title": "Integration status"}, {"path": "/investigations/:id", "title": "Investigation details"}]})

    @app.get("/api/integrations/status")
    def integrations():
        return jsonify(integration_status())

    @app.get("/api/investigations")
    def investigations():
        with db() as c:
            rows = c.execute("SELECT id,title,subject,sender,risk_level,risk_score,status,created_at FROM investigations ORDER BY created_at DESC").fetchall()
        return jsonify([dict(x) for x in rows])

    @app.post("/api/investigations")
    def create():
        try:
            payload = request.get_json(silent=True) or {}
            raw = payload.get("content", "") if request.is_json else request.form.get("content", "")
            upload = request.files.get("email_file")
            title = ((payload.get("title") if request.is_json else request.form.get("title")) or "Untitled investigation")[:200]
            if upload and upload.filename:
                if not upload.filename.lower().endswith(".eml"):
                    return error("Only .eml files are supported")
                raw = upload.read(Config.MAX_UPLOAD_BYTES + 1)
            if not raw or not raw.strip():
                return error("Paste an email or upload an .eml file")
            parsed = parse_email_input(raw)
            indicators = extract_indicators(parsed)
            findings = run_rules(parsed, indicators)
            file_scan = None
            attachment = request.files.get("attachment")
            if attachment and attachment.filename:
                ext = Path(secure_filename(attachment.filename)).suffix.lower()
                if ext not in Config.SUPPORTED_ATTACHMENT_EXTENSIONS:
                    return error("Unsupported attachment type")
                name = secrets.token_hex(8) + "_" + secure_filename(attachment.filename)
                path = Path(app.config["UPLOAD_FOLDER"]) / name
                attachment.save(path)
                file_scan = scan_file(path)
            ai = analyze_with_llm(parsed, indicators, findings)
            risk = score_risk(findings, ai, file_scan)
            timestamp = now()
            with db() as c:
                cur = c.execute("INSERT INTO investigations(title,subject,sender,recipients,risk_level,risk_score,raw_email,parsed_json,indicators_json,findings_json,ai_json,file_scan_json,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (title, parsed["subject"], parsed["from"], json.dumps(parsed["to"]), risk["level"], risk["score"], parsed["raw"], json.dumps(parsed), json.dumps(indicators), json.dumps(findings), json.dumps(ai), json.dumps(file_scan), "analyzed", timestamp, timestamp))
                iid = cur.lastrowid
                audit_event(c, iid, "investigation_created", risk)
                c.commit()
            if request.is_json:
                return jsonify({"id": iid, "risk": risk}), 201
            flash("Investigation created and analyzed.", "success")
            return redirect(url_for("detail", iid=iid))
        except ValueError as exc:
            return error(str(exc))
        except Exception:
            app.logger.exception("safe investigation failure")
            return error("The investigation could not be processed safely", 500)

    @app.get("/investigations/<int:iid>")
    def detail(iid):
        item = load(iid)
        return render_template("investigation.html", i=item) if item else (render_template("error.html", message="Investigation not found"), 404)

    @app.get("/api/investigations/<int:iid>")
    def detail_api(iid):
        item = load(iid)
        return jsonify(item) if item else error("Investigation not found", 404)

    @app.post("/api/investigations/<int:iid>/decision")
    def decision(iid):
        payload = request.get_json(silent=True) or {}
        choice = payload.get("decision", "")
        notes = str(payload.get("notes", ""))[:2000]
        if choice not in {"escalate", "close", "monitor", "undecided"}:
            return error("Invalid analyst decision")
        with db() as c:
            if not c.execute("SELECT 1 FROM investigations WHERE id=?", (iid,)).fetchone():
                return error("Investigation not found", 404)
            c.execute("INSERT INTO decisions(investigation_id,decision,notes,created_at) VALUES(?,?,?,?)", (iid, choice, notes, now()))
            c.execute("UPDATE investigations SET analyst_decision=?,analyst_notes=?,updated_at=? WHERE id=?", (choice, notes, now(), iid))
            audit_event(c, iid, "analyst_decision", {"decision": choice})
            c.commit()
        return jsonify({"status": "saved", "decision": choice})

    @app.get("/api/investigations/<int:iid>/report")
    def report(iid):
        item = load(iid)
        if not item:
            return error("Investigation not found", 404)
        html = generate_report(item)
        if request.args.get("download") == "1":
            path = Path(app.config["UPLOAD_FOLDER"]) / f"report_{iid}.html"
            path.write_text(html, encoding="utf-8")
            return send_file(path, as_attachment=True, download_name=path.name)
        return html

    return app

app = create_app()
if __name__ == "__main__":
    app.run(host=Config.HOST, port=Config.PORT, debug=False)
