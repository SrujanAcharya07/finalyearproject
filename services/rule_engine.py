import re
from urllib.parse import urlparse
def run_rules(parsed,ind):
 out=[]; sender=parsed.get("from",""); body=parsed.get("body","").lower()
 if ind["suspicious_phrases"]: out.append({"code":"social_engineering_language","severity":2,"title":"Urgent or sensitive-request language","evidence":ind["suspicious_phrases"]})
 if ind["ips"]: out.append({"code":"ip_url_or_text","severity":3,"title":"IP address present","evidence":ind["ips"]})
 if ind["urls"] and any(urlparse(u).hostname and urlparse(u).hostname!=ind["sender_domain"] for u in ind["urls"]): out.append({"code":"domain_mismatch","severity":3,"title":"URL domain differs from sender domain","evidence":ind["domains"]})
 if parsed.get("attachments"): out.append({"code":"unexpected_attachment","severity":2,"title":"Attachment requires inspection","evidence":parsed["attachments"]})
 auth=parsed.get("headers",{}).get("Authentication-Results")
 if not auth: out.append({"code":"auth_unavailable","severity":0,"title":"Email authentication evidence unavailable","evidence":"No Authentication-Results header"})
 if re.search(r"display.?name",sender,re.I): out.append({"code":"display_name_review","severity":1,"title":"Review display name and address alignment","evidence":sender})
 return out
