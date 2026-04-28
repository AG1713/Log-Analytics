import smtplib
from datetime import datetime
from email.mime.text import MIMEText

from bson import ObjectId
from fastapi import APIRouter, Query, Request, HTTPException

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

    if not hostname:
        return {"paths": []}
    query["hostname"] = hostname
    doc = config_db.settings.find_one(query)
    if not doc:
        return {"paths": []}
    return {"paths": doc["paths"]}

@router.post("/add_path")
async def add_path(request: Request):
    # 1. Catch JSON parsing errors
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")
    
    print(data)
    new_path = data.get("path")
    hostname = data.get("hostname")

    if not new_path:
        raise HTTPException(status_code=400, detail="No path provided")

    # 2. Wrap DB operations in a try/except block
    try:
        # First, check if this exact path is already being monitored (regardless of status)
        existing_path = config_db.settings.find_one({
            "type": "watch_config",
            "hostname": hostname,
            "paths.path": new_path  # Querying inside the array of objects
        })

        if existing_path:
            print(f"[*] Ignored: Path '{new_path}' is already in the array.")
            return {"status": "success", "message": "Path already exists"}

        # 3. If it doesn't exist, push the new path object with PENDING status
        path_object = {
            "path": new_path,
            "status": "PENDING"
        }

        result = config_db.settings.update_one(
            {"type": "watch_config", "hostname": hostname},
            {"$push": {"paths": path_object}},
            upsert=True
        )
        
        if result.modified_count > 0:
            print(f"[*] New path added to existing document: {new_path} (PENDING)")
            return {"status": "success", "added": new_path, "state": "PENDING"}
            
        elif result.upserted_id:
            print(f"[*] Created new document and added path: {new_path} (PENDING)")
            return {"status": "success", "added": new_path, "state": "PENDING", "upserted": True}

    except Exception as e:
        # 4. Catch and log the actual database error
        print(f"[!] Database operation failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal database error")


@router.put("/update_path_status")
async def update_path_status(request: Request):
    # 1. Parse the raw JSON payload, matching your previous style
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    # 2. Extract the variables manually
    hostname = data.get("hostname")
    target_path = data.get("path")
    new_status = data.get("status")

    # 3. Basic validation to ensure the agent sent everything we need
    if not hostname or not target_path or not new_status:
        raise HTTPException(status_code=400, detail="Missing required fields: hostname, path, or status")

    # 4. Execute the database update
    try:
        result = config_db.settings.update_one(
            {
                "type": "watch_config", 
                "hostname": hostname,
                "paths.path": target_path  # Find the specific path inside the array
            },
            {
                "$set": {"paths.$.status": new_status}  # Update only that path's status
            }
        )

        if result.modified_count > 0:
            print(f"[*] FIM State Machine: Updated {target_path} to [{new_status}] on {hostname}")
            return {"status": "success", "message": "Status updated successfully"}
            
        elif result.matched_count > 0:
            return {"status": "success", "message": "Status unchanged"}
            
        else:
            print(f"[!] FIM State Machine: Could not find path {target_path} to update.")
            raise HTTPException(status_code=404, detail="Path or host configuration not found")

    except Exception as e:
        print(f"[!] Database error in update_path_status: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


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
async def create_alert(alert_data: dict):
    # Convert the ISO string back into a Python datetime object
    if "timestamp" in alert_data:
        alert_data["timestamp"] = datetime.fromisoformat(alert_data["timestamp"])
    
    # Now PyMongo will see a datetime object and store a BSON Date!
    db.alerts.insert_one(alert_data)
    return {"status": "success"}


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



@router.post("/api/agents/register")
async def register_agent(request: Request):
    """Registers an agent or updates its last_active heartbeat."""
    data = await request.json()
    hostname = data.get("hostname")
    
    if not hostname:
        raise HTTPException(status_code=400, detail="Missing 'hostname' in request body")

    now = datetime.now(timezone.utc)
    
    try:
        db.agents.update_one(
            {"hostname": hostname},
            {
                "$set": {"last_active": now, "status": "online"},
                "$setOnInsert": {"first_seen": now}
            },
            upsert=True
        )
        return {"status": "success", "message": f"Agent {hostname} registered."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --- FIM BASELINE ENDPOINTS ---

@router.get("/api/fim/baseline/{hostname}")
async def get_fim_baseline(hostname: str):
    """Fetches the current FIM baseline for a specific host."""
    try:
        # Retrieve the baseline, excluding the MongoDB '_id' field
        docs = fim_db.file_baselines.find({"hostname": hostname}, {"_id": 0, "filepath": 1, "hash": 1})
        return list(docs)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/fim/baseline")
async def upsert_fim_baseline(request: Request):
    """Updates or inserts a file hash into the baseline."""
    data = await request.json()
    hostname = data.get("hostname")
    filepath = data.get("filepath")
    file_hash = data.get("hash")
    
    if not all([hostname, filepath, file_hash]):
        raise HTTPException(status_code=400, detail="Missing 'hostname', 'filepath', or 'hash' in request body")

    now = datetime.now(timezone.utc)
    
    try:
        fim_db.file_baselines.update_one(
            {"hostname": hostname, "filepath": filepath},
            {"$set": {
                "hash": file_hash,
                "last_check": now
            }},
            upsert=True
        )
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/api/fim/baseline")
async def delete_fim_baseline(hostname: str, filepath: str):
    """Removes a file from the baseline (used when a file is deleted)."""
    if not hostname or not filepath:
        raise HTTPException(status_code=400, detail="Missing 'hostname' or 'filepath' query parameters")

    try:
        result = fim_db.file_baselines.delete_one({"hostname": hostname, "filepath": filepath})
        if result.deleted_count == 1:
            return {"status": "success"}
        else:
            raise HTTPException(status_code=404, detail="Filepath not found in baseline")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))