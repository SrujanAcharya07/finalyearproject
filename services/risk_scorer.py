def score_risk(findings,ai=None,file_scan=None):
 score=min(100,sum(int(x.get("severity",0))*15 for x in findings)); reasons=[x["title"] for x in findings if x.get("severity",0)>0]
 if file_scan and file_scan.get("matches"): score=min(100,score+35); reasons.append("YARA match requires further investigation")
 level="Critical" if score>=80 else "High" if score>=50 else "Medium" if score>=20 else "Low"
 return {"score":score,"level":level,"reasons":reasons,"disclaimer":"Decision support only; not a guaranteed malware verdict."}
