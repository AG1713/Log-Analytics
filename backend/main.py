from fastapi import FastAPI, Request, Query
from ml_service import generate_attack_summary
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from bson import ObjectId
import smtplib
from email.mime.text import MIMEText
from fastapi.responses import StreamingResponse
import asyncio
import json

app = FastAPI()

# --- CONFIGURATION ---
GMAIL_USER        = "your_actual_email@gmail.com"
GMAIL_APP_PASSWORD = "abcd efgh ijkl mnop"
VICTIM_EMAIL      = "target_recipient@example.com"

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5173/fim",
        "http://localhost:5174",
        "http://127.0.0.1:5173",
        "http://172.17.0.4:5173",
        "http://172.17.0.1:5173"
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- DB CONNECTIONS ---
client = MongoClient("mongodb://172.17.0.1:27017/")
db         = client.siem_db
config_db  = client.siem_config
fim_db     = client.fim_integrity

# --- HELPERS ---

def serialize(doc):
    doc["_id"] = str(doc["_id"])
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
    msg['Subject'] = subject
    msg['From']    = GMAIL_USER
    msg['To']      = VICTIM_EMAIL
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
            server.sendmail(GMAIL_USER, VICTIM_EMAIL, msg.as_string())
        print(f"[+] Email alert sent to {VICTIM_EMAIL}")
    except Exception as e:
        print(f"[!] Email failed: {e}")

def find_duplicate_hostnames():
    collection = db["network_logs"]
    pipeline = [
        {
            "$group": {
                "_id": {"host": "$hostname", "ip": "$src_ip"},
                "last_active": {"$max": "$timestamp"}
            }
        },
        {
            "$group": {
                "_id": "$_id.host",
                "claiming_ips": {"$push": "$_id.ip"},
                "count": {"$sum": 1}
            }
        },
        {
            "$match": {"count": {"$gt": 1}}
        }
    ]
    results = list(collection.aggregate(pipeline))
    for res in results:
        res["alert_message"]  = f"CRITICAL: Hostname '{res['_id']}' is being used by {res['count']} different machines."
        res["action_required"] = "CHANGE_HOSTNAME_IMMEDIATELY"
    return results

# --- SECURITY ENDPOINTS ---

@app.get("/api/check-duplicates")
async def get_duplicates():
    return find_duplicate_hostnames()

# --- DEVICES ---

@app.get("/api/devices")
async def get_devices():
    """Returns all unique hostnames that have ever sent data."""
    hostnames = db.alerts.distinct("hostname") + \
                db.network_logs.distinct("hostname")
    return {"devices": list(set(h for h in hostnames if h))}

# --- FIM CONFIG ---

@app.get("/api/config")
async def get_config(hostname: str = Query(default=None)):
    query = {"type": "watch_config"}
    if hostname:
        query["hostname"] = hostname
    doc = config_db.settings.find_one(query)
    if not doc:
        return {"paths": ["/etc/nginx", "/var/www/html"]}
    return {"paths": doc["paths"]}

@app.post("/api/add_path")
async def add_path(request: Request):
    data     = await request.json()
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
        upsert=True
    )
    print(f"[*] New path added to monitoring: {new_path}")
    return {"status": "success", "added": new_path}

@app.delete("/api/config/path")
async def remove_path(request: Request):
    data     = await request.json()
    path     = data.get("path")
    hostname = data.get("hostname")
    if not path:
        return {"status": "error", "message": "No path provided"}
    query = {"type": "watch_config"}
    if hostname:
        query["hostname"] = hostname
    config_db.settings.update_one(query, {"$pull": {"paths": path}})
    return {"status": "success", "removed": path}

# --- FIM ALERTS ---

@app.post("/api/alerts")
async def receive_alert(request: Request):
    alert_data = await request.json()
    result = db.alerts.insert_one(alert_data)
    send_email_notification(
        alert_data.get("type", "FIM_ALERT"),
        alert_data.get("file", "Unknown"),
        alert_data.get("severity", "High")
    )
    print(f"[+] FIM Alert Received and Saved: {result.inserted_id}")
    return {"status": "success", "id": str(result.inserted_id)}

@app.get("/api/alerts")
async def get_alerts(hostname: str = Query(default=None)):
    query = {}
    if hostname:
        query["hostname"] = hostname
    alerts = list(db.alerts.find(query).sort("_id", -1))
    return [serialize(a) for a in alerts]

@app.delete("/api/alerts/{alert_id}")
async def delete_alert(alert_id: str):
    result = db.alerts.delete_one({"_id": ObjectId(alert_id)})
    if result.deleted_count:
        return {"status": "success"}
    return {"status": "error", "message": "Alert not found"}

@app.delete("/api/alerts")
async def clear_alerts(hostname: str = Query(default=None)):
    query = {}
    if hostname:
        query["hostname"] = hostname
    result = db.alerts.delete_many(query)
    return {"status": "success", "deleted": result.deleted_count}

# --- NETWORK LOGS ---

@app.get("/api/network/logs")
async def get_network_logs(
    hostname: str = Query(default=None),
    limit: int = Query(default=50)
):
    query = {}
    if hostname:
        query["hostname"] = hostname
    logs = list(db.network_logs.find(query).sort("_id", -1).limit(limit))
    return [serialize(l) for l in logs]

@app.get("/api/network/summary")
async def get_network_summary(hostname: str = Query(default=None)):
    query        = {"hostname": hostname} if hostname else {}
    pipeline_base = [{"$match": query}] if query else []

    # The below are just MongoDB aggregate queries
    total = db.network_logs.count_documents(query)
    proto_counts = {
        d["_id"]: d["count"]
        for d in db.network_logs.aggregate(pipeline_base + [
            {"$group": {"_id": "$proto", "count": {"$sum": 1}}}
        ])
    }
    top_ips = [
        {"ip": d["_id"], "count": d["count"]}
        for d in db.network_logs.aggregate(pipeline_base + [
            {"$group": {"_id": "$src_ip", "count": {"$sum": 1}}},
            {"$sort":  {"count": -1}},
            {"$limit": 5}
        ])
    ]
    return {
        "total":              total,
        "proto_distribution": proto_counts,
        "top_source_ips":     top_ips,
    }

# --- FIM BASELINES ---

@app.get("/api/fim/baselines")
async def get_baselines(hostname: str = Query(default=None)):
    query = {}
    if hostname:
        query["hostname"] = hostname
    files = list(fim_db.file_baselines.find(query).limit(100))
    return [serialize(f) for f in files]


# --- Realtime logs ---

@app.get("/api/network/stream")
async def stream_network_logs(hostname: str = Query(default=None)):
    async def event_generator():
        last_id = None
        while True:
            try:
                query = {}
                if hostname:
                    query["hostname"] = hostname
                if last_id:
                    query["_id"] = {"$gt": last_id}

                logs = list(
                    db.network_logs
                    .find(query)
                    .sort("_id", -1)
                    .limit(20)
                )

                if logs:
                    last_id = logs[0]["_id"]
                    for log in logs:
                        log["_id"] = str(log["_id"])
                        if "timestamp" in log:
                            log["timestamp"] = str(log["timestamp"])

                    yield f"data: {json.dumps(logs)}\n\n"

                await asyncio.sleep(3)
            except Exception as e:
                yield f"data: {json.dumps({'error': str(e)})}\n\n"
                await asyncio.sleep(5)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        }
    )


# --- ML SUMMARY ---

@app.get("/attack_summary")
def attack_summary():
    return generate_attack_summary()

# Before running backend:
#   1) python -m venv venv
#   2) venv\Scripts\activate
#   3) pip install -r requirements.txt
# To run: uvicorn main:app --reload