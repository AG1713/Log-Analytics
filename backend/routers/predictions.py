import asyncio
import json
from datetime import datetime
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pymongo.errors import PyMongoError
from bson import ObjectId

from database import db

router = APIRouter(prefix="/api/predictions", tags=["Predictions"])


def serialize(doc):
    if not doc:
        return doc
        
    try:
        doc = dict(doc) 
    except Exception as e:
        print(f"🚨 Serialization Error: Could not convert document to dict. Error: {e}", flush=True)
        return None 

    for key, value in list(doc.items()): 
        try:
            if isinstance(value, ObjectId):
                doc[key] = str(value)
            elif isinstance(value, datetime):
                doc[key] = value.isoformat()
        except Exception as e:
            print(f"🚨 Serialization Error on field '{key}' (Type: {type(value)}): {e}", flush=True)
            doc[key] = str(value) 

    return doc


@router.get("/logs")
def get_logs(limit: int = 50, hostname: str = Query(default=None)):
    try:
        query = {}
        if hostname:
            query["hostname"] = hostname
        logs = list(db.predictions.find(query).sort("timestamp", -1).limit(limit))
        return [serialize(log) for log in logs]
    except PyMongoError as e:
        raise HTTPException(status_code=500, detail=f"MongoDB error: {str(e)}")


@router.get("/stream")
async def stream_predictions(request: Request, hostname: str = Query(default=None)):
    """Streams live prediction logs via Server-Sent Events (SSE)."""
    async def event_generator():
        latest_doc = db.predictions.find_one(sort=[("timestamp", -1)])
        last_time = latest_doc["timestamp"] if latest_doc else datetime.min

        while True:
            if await request.is_disconnected():
                break

            try:
                query = {"timestamp": {"$gte": last_time}}
                if hostname:
                    query["hostname"] = hostname

                new_docs = list(db.predictions.find(query).sort([("timestamp", 1), ("_id", 1)]))

                if new_docs:
                    last_time = new_docs[-1]["timestamp"]
                    payload = [serialize(doc) for doc in new_docs]
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