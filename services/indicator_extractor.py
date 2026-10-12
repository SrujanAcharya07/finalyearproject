import hashlib,re
from urllib.parse import urlparse
URL_RE=re.compile(r"https?://[^\s<>\"]+",re.I); IP_RE=re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
PHRASES=["urgent","immediately","verify your account","password","one-time code","payment","wire transfer","gift card","confidential","click here"]
def extract_indicators(parsed):
 body=parsed.get("body",""); urls=URL_RE.findall(body); domains=[]
 for u in urls:
  try:
   h=urlparse(u).hostname
   if h: domains.append(h.lower())
  except ValueError: pass
 return {"urls":urls,"domains":sorted(set(domains)),"ips":sorted(set(IP_RE.findall(body))),"suspicious_phrases":[p for p in PHRASES if p.lower() in body.lower()],"attachments":parsed.get("attachments",[]),"sender_domain":(parsed.get("from","@").split("@")[-1].strip("> ").lower() if "@" in parsed.get("from","") else "")}
