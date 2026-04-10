import smtplib
from datetime import datetime
from email.mime.text import MIMEText

from bson import ObjectId
from fastapi import APIRouter, Query, Request

from database import db, config_db, fim_db

router = APIRouter(prefix="/api", tags=["FIM"])

GMAIL_USER        = "your_actual_email@gmail.com"
GMAIL_APP_PASSWORD = "abcd efgh ijkl mnop"
VICTIM_EMAIL      = "target_recipient@example.com"


def serialize(doc):
    doc["_id"] = str(doc["_id"])
    for key, value in doc.items():
        if isinstance(value, datetime):
            doc[key] = value.isoformat()
    return doc


def send_email_notification(alert_type, file_path, severity):
    subject = f"⚠️ SIEM ALERT: {alert_type}"
    body = f"""
    Security Alert Detected:
    ------------------------
    Event Type: {alert_type}
    File Path:  {file_path}
    Severity:   {severity}
    Timestamp:  (Automatic Logged)

    Please investigate the server immediately.
    """
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = GMAIL_USER
    msg["To"] = VICTIM_EMAIL

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
            server.sendmail(GMAIL_USER, VICTIM_EMAIL, msg.as_string())
        print(f"[+] Email alert sent to {VICTIM_EMAIL}")
    except Exception as e:
        print(f"[!] Email failed: {e}")


@router.get("/config")
async def get_config(hostname: str = Query(default=None)):
    query = {"type": "watch_config"}
    if hostname:
        query["hostname"] = hostname
    doc = config_db.settings.find_one(query)
    if not doc:
        return {"paths": ["/etc/nginx", "/var/www/html"]}
    return {"paths": doc["paths"]}


@router.post("/add_path")
async def add_path(request: Request):
    data = await request.json()
    new_path = data.get("path")
    hostname = data.get("hostname")

    if not new_path:
        return {"status": "error", "message": "No path provided"}

    query = {"type": "watch_config"}
    if hostname:
        query["hostname"] = hostname

    config_db.settings.update_one(
        query,
        {"$addToSet": {"paths": new_path}},
        upsert=True,
    )
    print(f"[*] New path added to monitoring: {new_path}")
    return {"status": "success", "added": new_path}


@router.delete("/config/path")
async def remove_path(request: Request):
    data = await request.json()
    path = data.get("path")
    hostname = data.get("hostname")

    if not path:
        return {"status": "error", "message": "No path provided"}

    query = {"type": "watch_config"}
    if hostname:
        query["hostname"] = hostname

    config_db.settings.update_one(query, {"$pull": {"paths": path}})
    return {"status": "success", "removed": path}


@router.post("/alerts")
async def receive_alert(request: Request):
    alert_data = await request.json()
    result = db.alerts.insert_one(alert_data)

    send_email_notification(
        alert_data.get("type", "FIM_ALERT"),
        alert_data.get("file", "Unknown"),
        alert_data.get("severity", "High"),
    )
    print(f"[+] FIM Alert Received and Saved: {result.inserted_id}")
    return {"status": "success", "id": str(result.inserted_id)}


@router.get("/alerts")
async def get_alerts(hostname: str = Query(default=None)):
    query = {}
    if hostname:
        query["hostname"] = hostname
    alerts = list(db.alerts.find(query).sort("_id", -1))
    return [serialize(a) for a in alerts]


@router.delete("/alerts/{alert_id}")
async def delete_alert(alert_id: str):
    result = db.alerts.delete_one({"_id": ObjectId(alert_id)})
    if result.deleted_count:
        return {"status": "success"}
    return {"status": "error", "message": "Alert not found"}


@router.delete("/alerts")
async def clear_alerts(hostname: str = Query(default=None)):
    query = {}
    if hostname:
        query["hostname"] = hostname
    result = db.alerts.delete_many(query)
    return {"status": "success", "deleted": result.deleted_count}


@router.get("/fim/baselines")
async def get_baselines(hostname: str = Query(default=None)):
    query = {}
    if hostname:
        query["hostname"] = hostname
    files = list(fim_db.file_baselines.find(query).limit(100))
    return [serialize(f) for f in files]