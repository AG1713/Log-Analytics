from fastapi import FastAPI, Request, Query, HTTPException
from dataset_summary import generate_attack_summary
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from bson import ObjectId
import smtplib
from email.mime.text import MIMEText
from fastapi.responses import StreamingResponse
import asyncio
import json
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from ml_worker import predict_log

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🚀 Starting background worker")
    task = asyncio.create_task(worker())
    yield
    task.cancel()

app = FastAPI(lifespan = lifespan)

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
client = MongoClient("mongodb://172.17.0.1:27018/")
db         = client.siem_db
config_db  = client.siem_config
fim_db     = client.fim_integrity

# --- HELPERS ---

# def serialize(doc):
#     doc["_id"] = str(doc["_id"])
#     return doc

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

# @app.get("/api/network/logs")
# async def get_network_logs(
#     hostname: str = Query(default=None),
#     limit: int = Query(default=50)
# ):
#     query = {}
#     if hostname:
#         query["hostname"] = hostname
#     logs = list(db.network_logs.find(query).sort("_id", -1).limit(limit))
#     return [serialize(l) for l in logs]

# @app.get("/api/network/summary")
# async def get_network_summary(hostname: str = Query(default=None)):
#     query        = {"hostname": hostname} if hostname else {}
#     pipeline_base = [{"$match": query}] if query else []

#     # The below are just MongoDB aggregate queries
#     total = db.network_logs.count_documents(query)
#     proto_counts = {
#         d["_id"]: d["count"]
#         for d in db.network_logs.aggregate(pipeline_base + [
#             {"$group": {"_id": "$proto", "count": {"$sum": 1}}}
#         ])
#     }
#     top_ips = [
#         {"ip": d["_id"], "count": d["count"]}
#         for d in db.network_logs.aggregate(pipeline_base + [
#             {"$group": {"_id": "$src_ip", "count": {"$sum": 1}}},
#             {"$sort":  {"count": -1}},
#             {"$limit": 5}
#         ])
#     ]
#     return {
#         "total":              total,
#         "proto_distribution": proto_counts,
#         "top_source_ips":     top_ips,
#     }

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
                    db.predictions
                    .find(query)
                    .sort("_id", -1)
                    .limit(20)
                )

                if logs:
                    last_id = logs[0]["_id"]
                    yield f"data: {json.dumps([serialize(l) for l in logs])}\n\n"  # ← use serialize() instead of manual conversion

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

# @app.get("/attack_summary")
# def attack_summary():
#     return generate_attack_summary()

# Before running backend:
#   1) python -m venv venv
#   2) venv\Scripts\activate
#   3) pip install -r requirements.txt
# To run: uvicorn main:app --reload


# -----------------------------------------------------------------------------------------------------------
# New endpoints
# -----------------------------------------------------------------------------------------------------------


# ============================
# 🔁 BACKGROUND WORKER
# ============================

def process_pending_logs():
    """
    Synchronous function containing the heavy lifting (DB + ML).
    This will be run in a separate thread.
    """
    logs = list(db.network_logs.find({
        "processed": {"$ne": True}
    }).limit(20))

    for log in logs:
        predict_log(log) # Heavy ML execution
        db.network_logs.update_one(
            {"_id": log["_id"]},
            {"$set": {"processed": True}}
        )

async def worker():
    """
    Asynchronous loop that schedules the heavy lifting without blocking.
    """
    while True:
        try:
            # Offload the blocking code to a separate thread
            await asyncio.to_thread(process_pending_logs)
            await asyncio.sleep(2)
        except Exception as e:
            print("[!] Worker error:", e)
            await asyncio.sleep(5)

# ============================
# 🔥 FIXED LOG INGESTION
# ============================

@app.post("/api/logs")
async def receive_logs(request: Request):
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    if isinstance(data, dict):
        logs = [data]
    elif isinstance(data, list):
        logs = data
    else:
        raise HTTPException(status_code=400, detail="Invalid format")

    for log in logs:
        log["received_at"] = datetime.utcnow()
        log["processed"] = False

    # Insert into database
    result = db.network_logs.insert_many(logs)

    # REMOVED predict_log() loop. The background worker will pick these up automatically!

    return {"status": "logs stored", "count": len(logs)}

# ============================
# 📊 SIMPLE DASHBOARD API
# ============================

@app.get("/api/attack-summary")
def attack_summary():

    total_records = db.network_logs.count_documents({})
    total_attacks = db.predictions.count_documents({"attack": {"$ne": "BENIGN"}})
    total_normal = db.predictions.count_documents({"attack": "BENIGN"})

    # 🔥 Attack distribution
    pipeline = [
        {"$group": {"_id": "$attack", "count": {"$sum": 1}}}
    ]
    attack_data = db.predictions.aggregate(pipeline)
    attack_distribution = {item["_id"]: item["count"] for item in attack_data}

    # 🔥 Severity distribution
    severity_data = db.predictions.aggregate([
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}}
    ])
    severity_distribution = {item["_id"]: item["count"] for item in severity_data}

    # 🔥 Protocol distribution
    proto_data = db.predictions.aggregate([
        {"$group": {"_id": "$proto", "count": {"$sum": 1}}}
    ])
    protocol_distribution = {item["_id"]: item["count"] for item in proto_data}

    # 🔥 Service distribution
    service_data = db.predictions.aggregate([
        {"$group": {"_id": "$service", "count": {"$sum": 1}}}
    ])
    service_distribution = {item["_id"]: item["count"] for item in service_data}

    return {
        "total_records": total_records,
        "total_attacks": total_attacks,
        "total_normal": total_normal,
        "attack_distribution": attack_distribution,
        "severity_distribution": severity_distribution,
        "protocol_distribution": protocol_distribution,
        "service_distribution": service_distribution
    }


# ============================
# 📊 LIVE ATTACK COUNT
# ============================

@app.get("/api/live-attacks")
def live_attacks():
    count = db.predictions.count_documents({"attack": {"$ne": "BENIGN"}})
    return {"live_attacks": count}


# ============================
# 📈 ATTACK TIMELINE
# ============================

@app.get("/api/attack-timeline")
def get_attack_timeline(hours: int = 6):
    """
    Returns an aggregated timeline of attacks vs normal traffic 
    grouped by hour for the specified time window.
    """
    # Calculate the time cutoff
    time_threshold = datetime.utcnow() - timedelta(hours=hours)

    # Note: Replace 'received_at' with 'timestamp' if your DB uses a different time field
    pipeline = [
        {"$match": {"received_at": {"$gte": time_threshold}}},
        {"$group": {
            "_id": {
                "year": {"$year": "$received_at"},
                "month": {"$month": "$received_at"},
                "day": {"$dayOfMonth": "$received_at"},
                "hour": {"$hour": "$received_at"}
            },
            "total_traffic": {"$sum": 1},
            "attacks": {
                "$sum": {"$cond": [{"$ne": ["$attack", "BENIGN"]}, 1, 0]}
            },
            "normal": {
                "$sum": {"$cond": [{"$eq": ["$attack", "BENIGN"]}, 1, 0]}
            }
        }},
        {"$sort": {"_id.year": 1, "_id.month": 1, "_id.day": 1, "_id.hour": 1}}
    ]

    results = list(db.predictions.aggregate(pipeline))

    # Format it nicely for your frontend charting library (like Chart.js or Recharts)
    formatted_data = []
    for res in results:
        # Reconstruct an ISO string for the hour block
        dt_str = f"{res['_id']['year']}-{res['_id']['month']:02d}-{res['_id']['day']:02d}T{res['_id']['hour']:02d}:00:00Z"
        
        formatted_data.append({
            "timestamp": dt_str,
            "total_traffic": res["total_traffic"],
            "attacks": res["attacks"],
            "normal": res["normal"]
        })

    return formatted_data

# ============================
# 📊 GET LOGS
# ============================

@app.get("/api/network/logs")
def get_logs(limit: int = 50):
    logs = list(
        db.predictions.find().sort("_id", -1).limit(limit)
    )
    return [serialize(l) for l in logs]


# ============================
# ❤️ HEALTH CHECK ???????????????????
# ============================

@app.get("/api/health")
def health():
    return {"status": "ok"}

# @app.get("/api/live-logs") # ???????????????
# def get_live_logs():
#     logs = list(
#         db.network_logs
#         .find({})
#         .sort("_id", -1)
#         .limit(20)
#     )

#     for log in logs:
#         log["_id"] = str(log["_id"])

#     return logs
