import asyncio
import json
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pymongo.errors import PyMongoError
from bson import ObjectId

from database import db

router = APIRouter(prefix="/api", tags=["Network"])


def serialize(doc):
    # Handle empty documents gracefully
    if not doc:
        return doc
        
    try:
        doc = dict(doc) 
    except Exception as e:
        print(f"🚨 Serialization Error: Could not convert document to dict. Error: {e}", flush=True)
        return None # Or raise the exception depending on how your API handles errors

    for key, value in list(doc.items()): # Using list() ensures safe iteration if dictionary changes size
        try:
            if isinstance(value, ObjectId):
                doc[key] = str(value)
            elif isinstance(value, datetime):
                doc[key] = value.isoformat()
            # Optional: Catch other weird types here in the future if needed
            
        except Exception as e:
            # It tells you exactly WHICH field broke and WHAT type it is.
            print(f"🚨 Serialization Error on field '{key}' (Type: {type(value)}): {e}", flush=True)
            
            # Safe fallback: forcefully cast it to a string so the API doesn't completely crash
            doc[key] = str(value) 

    return doc


@router.get("/devices")
async def get_devices():
    try:
        hostnames = (
            db.alerts.distinct("hostname")
            + db.network_logs.distinct("hostname")
            + db.predictions.distinct("hostname")
        )
        unique_hostnames = sorted({h for h in hostnames if h and str(h).strip()})
        return {"devices": unique_hostnames, "count": len(unique_hostnames)}
    except PyMongoError as e:
        raise HTTPException(status_code=500, detail=f"MongoDB error: {str(e)}")
    

@router.get("/network/logs")
def get_network_logs(limit: int = 50, hostname: str = Query(default=None)):
    try:
        query ={}
        if hostname:
            query["hostname"] = hostname
        # Fetching directly from network_logs
        logs = list(db.network_logs.find(query).sort("timestamp", -1).limit(limit))
        
        formatted_logs = []
        for log in logs:
            log["_id"] = str(log["_id"])  # Ensure ObjectId is serialized
            formatted_logs.append(log)
            
        return formatted_logs
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")


@router.get("/network/stream")
async def stream_network_logs(request: Request, hostname: str = Query(default=None)):
    """Streams live raw network logs via Server-Sent Events (SSE)."""
    async def event_generator():
        # 1. Initialize cursor at the "head" of the collection
        latest_doc = db.network_logs.find_one(sort=[("timestamp", -1)])
        last_time = latest_doc["timestamp"] if latest_doc else datetime.min

        while True:
            if await request.is_disconnected():
                break

            try:
                # 2. Query only for documents newer than our last seen ID
                query = {"timestamp": {"$gte": last_time}}
                if hostname:
                    query["hostname"] = hostname

                # 3. Fetch in ascending order (oldest to newest)
                new_docs = list(db.network_logs.find(query).sort([("timestamp", 1), ("_id", 1)]))

                if new_docs:
                    last_time = new_docs[-1]["timestamp"]
                    payload = [serialize(doc) for doc in new_docs]
                    yield f"data: {json.dumps(payload)}\n\n"

                await asyncio.sleep(3)

            except Exception as e:
                yield f"data: {json.dumps({'error': str(e)})}\n\n"
                await asyncio.sleep(5) # Backoff on error

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/predictions/logs")
def get_logs(limit: int = 50, hostname: str = Query(default=None)):
    try:
        query = {}
        if hostname:
            query["hostname"] = hostname
        logs = list(db.predictions.find(query).sort("timestamp", -1).limit(limit))
        return [serialize(log) for log in logs]
    except PyMongoError as e:
        raise HTTPException(status_code=500, detail=f"MongoDB error: {str(e)}")

@router.get("/predictions/stream")
async def stream_predictions(request: Request, hostname: str = Query(default=None)):
    """Streams live prediction logs via Server-Sent Events (SSE)."""
    async def event_generator():
        latest_doc = db.predictions.find_one(sort=[("timestamp", -1)])
        last_time = latest_doc["timestamp"] if latest_doc else datetime.min

        while True:
            if await request.is_disconnected():
                break

            try:
                # 2. Query only for documents newer than our last seen ID
                query = {"timestamp": {"$gte": last_time}}
                if hostname:
                    query["hostname"] = hostname

                # 3. Fetch in ascending order (oldest to newest)
                new_docs = list(db.predictions.find(query).sort([("timestamp", 1), ("_id", 1)]))

                if new_docs:
                    last_time = new_docs[-1]["timestamp"]
                    payload = [serialize(doc) for doc in new_docs]
                    yield f"data: {json.dumps(payload)}\n\n"

                await asyncio.sleep(3)

            except Exception as e:
                yield f"data: {json.dumps({'error': str(e)})}\n\n"
                await asyncio.sleep(5) # Backoff on error

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

    try:
        for log in logs:
            log["received_at"] = datetime.now(timezone.utc)
            log["processed"] = False
            if "timestamp" in log:
                log["timestamp"] = datetime.fromisoformat(log["timestamp"])

        result = db.network_logs.insert_many(logs)
        return {
            "status": "logs stored",
            "count": len(result.inserted_ids),
        }

    except PyMongoError as e:
        raise HTTPException(status_code=500, detail=f"MongoDB insert failed: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")
