import html
from services.url_defanger import defang_url
def generate_report(inv):
 i=inv; ind=i.get("indicators") or {}; findings=i.get("findings") or []; risk=i.get("risk") or {}; ai=i.get("ai") or {}
 urls="<br>".join(html.escape(defang_url(u)) for u in ind.get("urls",[])) or "None"
 fs="".join(f"<li>{html.escape(x.get('title',''))}: {html.escape(str(x.get('evidence','')))}</li>" for x in findings) or "<li>None</li>"
 return f"""<!doctype html><html><head><meta charset=utf-8><title>Investigation {i['id']}</title><style>body{{font:16px system-ui;max-width:900px;margin:40px auto;color:#10243e}}.risk{{color:#b42318;font-weight:700}}</style></head><body><h1>Incident Report #{i['id']}</h1><p><b>Created:</b> {html.escape(i['created_at'])}</p><p><b>Subject:</b> {html.escape(i.get('subject') or '')}</p><p><b>Sender:</b> {html.escape(i.get('sender') or '')}</p><p class=risk><b>Risk:</b> {html.escape(risk.get('level','Unknown'))} ({risk.get('score',0)}/100)</p><h2>Defanged URLs</h2><p>{urls}</p><h2>Rule findings</h2><ul>{fs}</ul><h2>AI advisory</h2><p>{html.escape(ai.get('summary','Unavailable'))}</p><h2>Limitations</h2><p>Risk scoring is decision support, not a guaranteed malware verdict. Suspicious URLs were not visited.</p></body></html>"""
