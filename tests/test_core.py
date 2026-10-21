import sys
from pathlib import Path

import pytest
import jwt
from datetime import datetime, timedelta, timezone
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_app
from config import Config
from services.email_parser import parse_email_input
from services.indicator_extractor import extract_indicators
from services.llm_analyzer import OllamaAssessment, _validate_payload, analyze_with_llm
from services.risk_scorer import score_risk
from services.rule_engine import run_rules
from services.url_defanger import defang_url

EMAIL = b"From: CFO <cfo@example.com>\nTo: user@example.net\nSubject: Urgent verification\n\nClick https://evil.example/login immediately to verify your password."
TEST_AUTH = {"MANUS_PROJECT_ID": "test-project", "MANUS_JWT_SECRET": "test-secret-012345678901234567890123", "MANUS_OAUTH_PORTAL_URL": "https://auth.example", "MANUS_OAUTH_API_URL": "https://api.example", "SESSION_COOKIE_SECURE": False}


def make_authenticated_client(app):
    token = jwt.encode({"openId": "test-user", "name": "Test Analyst", "appId": "test-project", "exp": datetime.now(timezone.utc) + timedelta(hours=1)}, "test-secret-012345678901234567890123", algorithm="HS256")
    client = app.test_client()
    client.set_cookie("webdev_app_session", token)
    return client


def test_parser_and_indicators():
    parsed = parse_email_input(EMAIL)
    indicators = extract_indicators(parsed)
    assert parsed["subject"] == "Urgent verification"
    assert "evil.example" in indicators["domains"]


def test_defang_and_score():
    assert defang_url("https://example.com/login") == "hxxps://example[.]com/login"
    assert score_risk([{"title": "x", "severity": 3}], None)["level"] == "Low"
    assert score_risk([{"title": "x", "severity": 2}, {"title": "y", "severity": 2}], None)["level"] == "Medium"


def test_phrase_categories_are_scored_independently():
    parsed = parse_email_input(b"From: security@example.com\nTo: user@example.net\nSubject: Urgent payment\n\nAct immediately. Verify your account password and send a wire transfer.")
    indicators = extract_indicators(parsed)
    findings = run_rules(parsed, indicators)
    codes = {item["code"] for item in findings}
    assert {"urgency_language", "credential_request", "payment_request"}.issubset(codes)
    result = score_risk(findings)
    assert result["score"] > 15
    assert result["level"] in {"Medium", "High", "Critical"}


def test_structured_assessment_validation():
    result = _validate_payload({"summary": "Suspicious request", "risk_assessment": "Review", "techniques": ["urgency"]})
    assert isinstance(result, OllamaAssessment)
    with pytest.raises(ValidationError):
        _validate_payload({"summary": "Missing risk field"})


def test_llm_unavailable_is_safe(monkeypatch):
    monkeypatch.setattr(Config, "OLLAMA_MODEL", "")
    result = analyze_with_llm({}, {}, [])
    assert result["status"] == "unavailable"
    assert result["advisory"] is True


def test_login_gate_keeps_public_endpoints_available(tmp_path):
    app = create_app({"TESTING": True, "DATABASE_PATH": str(tmp_path / "t.db"), "UPLOAD_FOLDER": str(tmp_path / "u"), **TEST_AUTH})
    client = app.test_client()
    assert client.get("/").status_code == 302
    assert client.get("/").headers["Location"].endswith("/auth/login")
    assert client.get("/auth/login").status_code == 200
    assert client.get("/health").status_code == 200
    assert client.get("/api/investigations").status_code == 401


def test_route_persistence(tmp_path, monkeypatch):
    monkeypatch.setattr(Config, "OLLAMA_MODEL", "")
    app = create_app({"TESTING": True, "DATABASE_PATH": str(tmp_path / "t.db"), "UPLOAD_FOLDER": str(tmp_path / "u"), **TEST_AUTH})
    client = make_authenticated_client(app)
    response = client.post("/api/investigations", json={"title": "test", "content": EMAIL.decode()})
    assert response.status_code == 201
    iid = response.get_json()["id"]
    assert client.get(f"/api/investigations/{iid}").status_code == 200
    assert client.get(f"/api/investigations/{iid}/report").status_code == 200


def test_invalid_input(tmp_path):
    app = create_app({"TESTING": True, "DATABASE_PATH": str(tmp_path / "t.db"), "UPLOAD_FOLDER": str(tmp_path / "u"), **TEST_AUTH})
    assert make_authenticated_client(app).post("/api/investigations", json={}).status_code == 400
