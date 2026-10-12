from email import policy
from email.parser import BytesParser
from email.utils import getaddresses

def parse_email_input(raw):
    if isinstance(raw,str): raw=raw.encode("utf-8",errors="replace")
    if len(raw)>10*1024*1024: raise ValueError("Email content is too large.")
    try: msg=BytesParser(policy=policy.default).parsebytes(raw)
    except Exception as e: raise ValueError("The email could not be parsed as a valid .eml message.") from e
    body=[]; attachments=[]
    if msg.is_multipart():
        for part in msg.walk():
            if part.is_attachment(): attachments.append({"filename":part.get_filename() or "unnamed","content_type":part.get_content_type()})
            elif part.get_content_type()=="text/plain": body.append(part.get_content())
    else: body=[msg.get_content()] if msg.get_content_type().startswith("text/") else []
    to=[a for _,a in getaddresses(msg.get_all("to",[])) if a]
    return {"raw":raw.decode("utf-8",errors="replace"),"subject":str(msg.get("subject", "")),"from":str(msg.get("from", "")),"to":to,"date":str(msg.get("date", "")),"headers":{k:str(v) for k,v in msg.items()},"body":"\n".join(body),"attachments":attachments}
