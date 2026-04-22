from fastapi import APIRouter, HTTPException
from typing import Optional
from datetime import datetime, timezone, timedelta
from bson import ObjectId
from database import db
from routers.network_logs import serialize

router = APIRouter(
    prefix="/api/attack_alerts",
    tags=["Attack Alerts"]
)

# --- Endpoints ---

@router.get("/")
def get_alerts(
    limit: int = 100, 
    skip: int = 0, 
    status: Optional[str] = None,
    include_archived: bool = False,
    hostname: Optional[str] = None
):
    """Fetch alerts, optionally filtered by status (e.g., 'Inactive', 'Resolved')."""
    query = {}
    query["event_count"] = {"$gt": 10}
    if not include_archived:
        query["is_archived"] = {"$ne": True}

    if status:
        query["status"] = status

    if hostname:
        query["hostname"] = hostname
        
    alerts_cursor = db["attack_alerts"].find(query).skip(skip).limit(limit).sort("last_seen", -1)
    
    # Convert cursor to list and format the _id for each alert
    alerts = [serialize(alert) for alert in alerts_cursor]
    return alerts

@router.post("/{alert_id}/toggle")
def toggle_alert_status(alert_id: str, idle_minutes: int = 1):
    """Toggles the alert status between 'Inactive' and 'Resolved'."""
    if not ObjectId.is_valid(alert_id):
        raise HTTPException(status_code=400, detail="Invalid Alert ID")

    # Fetch the current alert
    alert = db.attack_alerts.find_one({"_id": ObjectId(alert_id)})
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    # Determine new status
    current_status = alert.get("status", "Inactive")
    last_seen = alert.get("last_seen", datetime.now(timezone.utc))
    stale_threshold = datetime.utcnow() - timedelta(minutes=idle_minutes)
    
    if current_status == "Resolved":
        if last_seen < stale_threshold:
            new_status = "Inactive"
            resolved_at = None
        else:
            new_status = "Active"
            resolved_at = None
    else:
        new_status = "Resolved"
        resolved_at = datetime.now(timezone.utc)

    # Update the document
    update_result = db.attack_alerts.find_one_and_update(
        {"_id": ObjectId(alert_id)},
        {"$set": {"status": new_status, "resolved_at": resolved_at}},
        return_document=True 
    )

    return serialize(update_result)

@router.delete("/{alert_id}")
def soft_delete_alert(alert_id: str):
    """Soft deletes an alert by setting is_archived to True."""
    if not ObjectId.is_valid(alert_id):
        raise HTTPException(status_code=400, detail="Invalid Alert ID format")

    # Update the document to set is_archived = True
    update_result = db.attack_alerts.find_one_and_update(
        {"_id": ObjectId(alert_id)},
        {"$set": {"is_archived": True}},
        return_document=True 
    )
    
    if not update_result:
        raise HTTPException(status_code=404, detail="Alert not found")

    return serialize(update_result)