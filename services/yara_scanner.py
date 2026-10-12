from pathlib import Path
def scan_file(path):
 if path is None:
  try: import yara
  except ImportError: return {"status":"unavailable","matches":[],"detail":"yara-python is not installed"}
  return {"status":"available","matches":[],"detail":"No scan requested"}
 try:
  import yara
  rules_path=Path(__file__).resolve().parent.parent/"rules.yar"
  if not rules_path.exists(): return {"status":"unavailable","matches":[],"detail":"Trusted local rules file is not configured"}
  rules=yara.compile(filepath=str(rules_path)); matches=[m.rule for m in rules.match(str(path),timeout=5)]
  return {"status":"completed","matches":matches,"detail":"A match is an indicator, not a verdict."}
 except ImportError: return {"status":"unavailable","matches":[],"detail":"yara-python is not installed"}
 except Exception: return {"status":"failed","matches":[],"detail":"Static scan failed safely"}
