import io,json,sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import create_app
from services.email_parser import parse_email_input
from services.indicator_extractor import extract_indicators
from services.url_defanger import defang_url
from services.risk_scorer import score_risk
EMAIL=b"From: CFO <cfo@example.com>\nTo: user@example.net\nSubject: Urgent verification\n\nClick https://evil.example/login immediately to verify your password."
def test_parser_and_indicators():
 p=parse_email_input(EMAIL); i=extract_indicators(p); assert p["subject"]=="Urgent verification"; assert "evil.example" in i["domains"]
def test_defang_and_score():
 assert defang_url("https://example.com/login")=="hxxps://example[.]com/login"; assert score_risk([{"title":"x","severity":3}],None)["level"]=="Medium"
def test_route_persistence(tmp_path):
 app=create_app({"TESTING":True,"DATABASE_PATH":str(tmp_path/"t.db"),"UPLOAD_FOLDER":str(tmp_path/"u")}); c=app.test_client(); r=c.post("/api/investigations",json={"title":"test","content":EMAIL.decode()}); assert r.status_code==201; iid=r.get_json()["id"]; assert c.get(f"/api/investigations/{iid}").status_code==200; assert c.get(f"/api/investigations/{iid}/report").status_code==200
def test_invalid_input(tmp_path):
 app=create_app({"TESTING":True,"DATABASE_PATH":str(tmp_path/"t.db"),"UPLOAD_FOLDER":str(tmp_path/"u")}); assert app.test_client().post("/api/investigations",json={}).status_code==400
