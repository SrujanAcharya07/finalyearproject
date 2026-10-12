import os
from pathlib import Path

BASE_DIR=Path(__file__).resolve().parent
class Config:
    SECRET_KEY=os.getenv("SECRET_KEY","dev-only-change-me")
    DATABASE_PATH=os.getenv("DATABASE_PATH",str(BASE_DIR/"database"/"app.db"))
    UPLOAD_FOLDER=os.getenv("UPLOAD_FOLDER",str(BASE_DIR/"uploads"))
    MAX_UPLOAD_BYTES=int(os.getenv("MAX_UPLOAD_BYTES","5242880"))
    SUPPORTED_ATTACHMENT_EXTENSIONS={".pdf",".doc",".docx",".xls",".xlsx",".txt",".zip",".png",".jpg",".jpeg"}
    HOST=os.getenv("HOST","127.0.0.1"); PORT=int(os.getenv("PORT","5000"))
    OLLAMA_BASE_URL=os.getenv("OLLAMA_BASE_URL",""); OLLAMA_MODEL=os.getenv("OLLAMA_MODEL","")
    CUCKOO_URL=os.getenv("CUCKOO_URL",""); CUCKOO_API_KEY=os.getenv("CUCKOO_API_KEY","")
    CORTEX_URL=os.getenv("CORTEX_URL",""); CORTEX_API_KEY=os.getenv("CORTEX_API_KEY","")
    THEHIVE_URL=os.getenv("THEHIVE_URL",""); THEHIVE_API_KEY=os.getenv("THEHIVE_API_KEY","")
