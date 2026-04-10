import asyncio
import json
from datetime import datetime

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from database import db

router = APIRouter(prefix="/api", tags=["Network"])


def serialize(doc):
    doc["_id"] = str(doc["_id"])
    for key, value in doc.items():
        if isinstance(value, datetime):
            doc[key] = value.isoformat()
    return doc


@router.get("/devices")
async def get_devices():
    """Returns all unique hostnames that have ever sent data."""
    hostnames = db.alerts.distinct("hostname") + db.network_logs.distinct("hostname")
    return {"devices": list(set(h for h in hostnames if h))}


@router.get("/network/stream")
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
                    payload = [serialize(log) for log in logs]
                    yield f"data: {json.dumps(payload)}\n\n"

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
        },
    )


@router.post("/logs")
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

    db.network_logs.insert_many(logs)
    return {"status": "logs stored", "count": len(logs)}


@router.get("/network/logs")
def get_logs(limit: int = 50):
    logs = list(db.predictions.find().sort("_id", -1).limit(limit))
    return [serialize(log) for log in logs]