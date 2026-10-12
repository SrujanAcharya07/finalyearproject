import json
from datetime import datetime,timezone
def audit_event(conn,investigation_id,event_type,detail): conn.execute("INSERT INTO audit_events (investigation_id,event_type,detail_json,created_at) VALUES (?,?,?,?)",(investigation_id,event_type,json.dumps(detail),datetime.now(timezone.utc).isoformat()))
