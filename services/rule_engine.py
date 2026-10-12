from urllib.parse import urlparse


PHRASE_RULES = (
    ("urgency_language", 2, "Urgent or threatening language", ("urgent", "immediately", "act now", "suspended today")),
    ("credential_request", 3, "Credential or verification-code request", ("password", "one-time code", "verification code", "verify your account")),
    ("payment_request", 3, "Payment or financial-change request", ("payment", "wire transfer", "gift card", "bank details")),
    ("click_action", 1, "Call-to-action language", ("click here", "click the link")),
)


def run_rules(parsed, indicators):
    findings = []
    body = parsed.get("body", "").lower()

    for code, severity, title, phrases in PHRASE_RULES:
        matched = [phrase for phrase in phrases if phrase in body]
        if matched:
            findings.append({"code": code, "severity": severity, "title": title, "evidence": matched})

    if indicators["ips"]:
        findings.append({"code": "ip_url_or_text", "severity": 3, "title": "IP address present", "evidence": indicators["ips"]})

    if indicators["urls"] and any(
        urlparse(url).hostname and urlparse(url).hostname != indicators["sender_domain"]
        for url in indicators["urls"]
    ):
        findings.append({"code": "domain_mismatch", "severity": 3, "title": "URL domain differs from sender domain", "evidence": indicators["domains"]})

    if parsed.get("attachments"):
        findings.append({"code": "unexpected_attachment", "severity": 2, "title": "Attachment requires inspection", "evidence": parsed["attachments"]})

    authentication_results = parsed.get("headers", {}).get("Authentication-Results")
    if not authentication_results:
        findings.append({"code": "auth_unavailable", "severity": 0, "title": "Email authentication evidence unavailable", "evidence": "No Authentication-Results header"})

    sender = parsed.get("from", "")
    if "@" in sender and "<" in sender and ">" in sender:
        display_name = sender.split("<", 1)[0].strip()
        address = sender.split("<", 1)[1].split(">", 1)[0].strip()
        local_part = address.split("@", 1)[0].lower() if "@" in address else ""
        if display_name and local_part and any(token in display_name.lower() for token in ("ceo", "cfo", "security", "support", "admin")):
            findings.append({"code": "display_name_review", "severity": 1, "title": "Review display name and address alignment", "evidence": sender})

    return findings
