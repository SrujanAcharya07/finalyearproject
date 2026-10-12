import requests
def submit_to_cuckoo(path,base_url,api_key=""):
 if not base_url: return {"status":"unavailable","detail":"Cuckoo is not configured"}
 try:
  with open(path,"rb") as f: r=requests.post(base_url.rstrip("/")+"/tasks/create/file",files={"file":f},headers={"Authorization":f"Bearer {api_key}"} if api_key else {},timeout=15)
  return {"status":"submitted" if r.ok else "failed","response":r.json() if r.headers.get("content-type","").startswith("application/json") else {}}
 except requests.RequestException: return {"status":"failed","detail":"Cuckoo request timed out or failed"}
