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
def get_network_logs(limit: int = 50):
    try:
        # Fetching directly from network_logs
        logs = list(db.network_logs.find().sort("timestamp", -1).limit(limit))
        
        formatted_logs = []
        for log in logs:
            log["_id"] = str(log["_id"])  # Ensure ObjectId is serialized
            formatted_logs.append(log)
            
        return formatted_logs
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")


@router.get("/network/stream")
async def stream_network(request: Request, hostname: str = None):
    """Streams live raw network logs via Server-Sent Events (SSE)."""
    
    async def log_generator():
        try:
            # 1. Find the latest document ID so we only stream NEW logs from this point forward
            latest_log = db.network_logs.find_one(sort=[("_id", -1)])
            last_id = latest_log["_id"] if latest_log else ObjectId("000000000000000000000000")

            while True:
                # 2. Break the loop if the user navigates away or toggles the stream off
                if await request.is_disconnected():
                    break

                # 3. Build query for logs newer than our last seen ID
                query = {"_id": {"$gt": last_id}}
                if hostname:
                    query["hostname"] = hostname

                # Fetch new logs in chronological order
                new_docs = list(db.network_logs.find(query).sort("_id", 1))

                if new_docs:
                    # Update our tracker to the newest ID
                    last_id = new_docs[-1]["_id"]
                    
                    # Format for frontend (fix the ObjectId serialization)
                    formatted_docs = []
                    for doc in new_docs:
                        doc["_id"] = str(doc["_id"])
                        formatted_docs.append(doc)

                    # 4. Yield the SSE formatted string (must start with 'data: ' and end with '\n\n')
                    yield f"data: {json.dumps(formatted_docs)}\n\n"

                # 5. Pause for 1 second before checking again to prevent CPU spam
                await asyncio.sleep(1)
                
        except Exception as e:
            # Send an error event to the frontend if something crashes
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return StreamingResponse(log_generator(), media_type="text/event-stream")


@router.get("/predictions/logs")
def get_logs(limit: int = 50):
    try:
        logs = list(db.predictions.find().sort("timestamp", -1).limit(limit))
        return [serialize(log) for log in logs]
    except PyMongoError as e:
        raise HTTPException(status_code=500, detail=f"MongoDB error: {str(e)}")

@router.get("/predictions/stream")
async def stream_network_logs(request: Request, hostname: str = Query(default=None)):
    async def event_generator():
        last_id = None

        while True:
            # Fix: detect client disconnect and stop the loop
            if await request.is_disconnected():
                break

            try:
                query = {}
                if hostname:
                    query["hostname"] = hostname
                if last_id:
                    query["_id"] = {"$gt": last_id}

                logs = list(
                    db.predictions.find(query).sort("timestamp", -1).limit(20)
                )

                if logs:
                    last_id = logs[-1]["_id"]
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
