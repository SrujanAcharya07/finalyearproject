def score_risk(findings, ai=None, file_scan=None):
    """Return a transparent preliminary score; one weak indicator stays Low."""
    weights = {1: 5, 2: 15, 3: 25, 4: 45}
    positive_findings = [item for item in findings if int(item.get("severity", 0)) > 0]
    score = min(100, sum(weights.get(int(item.get("severity", 0)), 0) for item in positive_findings))
    reasons = [item["title"] for item in positive_findings]
    yara_match = bool(file_scan and file_scan.get("matches"))
    if yara_match:
        score = min(100, score + 35)
        reasons.append("YARA match requires further investigation")

    evidence_count = len(positive_findings) + (1 if yara_match else 0)
    if score >= 80 and evidence_count >= 2:
        level = "Critical"
    elif score >= 50 and evidence_count >= 2:
        level = "High"
    elif score >= 30 and evidence_count >= 2:
        level = "Medium"
    else:
        level = "Low"

    return {
        "score": score,
        "level": level,
        "reasons": reasons,
        "evidence_count": evidence_count,
        "disclaimer": "Decision support only; not a guaranteed malware verdict.",
    }
