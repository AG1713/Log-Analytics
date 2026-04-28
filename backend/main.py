
from datetime import datetime, timedelta
import sys
import os
sys.path.append(os.path.dirname(__file__))
from fastapi import FastAPI
print("--- 2. Imported FastAPI ---", flush=True)
from fastapi.middleware.cors import CORSMiddleware
import asyncio
from contextlib import asynccontextmanager
from ml_worker import predict_log
print("--- 3. Imported ML Worker ---", flush=True)
from database import db
print("--- 4. Imported DB ---", flush=True)
from routers.dashboard import router as dashboard_router
from routers.fim import router as fim_router
from routers.network_logs import router as network_logs_router
from routers.attack_alerts import router as attack_alerts_router
#----------------------------------------------------------------------
from chatbotcore import parse_query, fetch_logs
from pydantic import BaseModel
#---------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🚀 Starting background worker")
    task = asyncio.create_task(worker())
    janitor_task = asyncio.create_task(alert_janitor())
    yield
    task.cancel()
    janitor_task.cancel()


app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5173",
        "http://172.17.0.4:5173",
        "http://172.17.0.1:5173"
        "http://localhost:5173/fim",
    ],
    allow_credentials=True,   # Added
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(dashboard_router)
app.include_router(fim_router)
app.include_router(network_logs_router)
app.include_router(attack_alerts_router)  # <-- Include the attack_alerts router


async def alert_janitor():
    """Runs in the background to clean up stale alerts every 60 seconds."""
    while True:
        # Run your synchronous DB sweep function in a thread so it doesn't block FastAPI
        await asyncio.to_thread(close_stale_alerts, idle_minutes=1)
        await asyncio.sleep(60) # Wait 60 seconds before sweeping again


def close_stale_alerts(idle_minutes=10):
    """Marks alerts as Resolved if no new logs have been seen for `idle_minutes`."""
    alerts_col = db["attack_alerts"]
    
    try:
        stale_threshold = datetime.utcnow() - timedelta(minutes=idle_minutes)
        
        # Find all Ongoing alerts where last_seen is older than the threshold
        result = alerts_col.update_many(
            {
                "status": "Active",
                "last_seen": {"$lt": stale_threshold}
            },
            {
                "$set": {
                    "status": "Inactive",  # Close the alert
                }
            }
        )
        
        if result.modified_count > 0:
            print(f"🔒 Auto-resolved {result.modified_count} stale alerts.")
            
    except Exception as e:
        print("❌ Error closing stale alerts:", e)


class ChatRequest(BaseModel):
    query: str

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
        res["alert_message"] = f"CRITICAL: Hostname '{res['_id']}' is being used by {res['count']} different machines."
        res["action_required"] = "CHANGE_HOSTNAME_IMMEDIATELY"
    return results


@app.get("/api/check-duplicates")
async def get_duplicates():
    return find_duplicate_hostnames()


def process_pending_logs():
    logs = list(db.network_logs.find({
        "processed": {"$ne": True}
    }).limit(20))
    for log in logs:
        predict_log(log)
        db.network_logs.update_one(
            {"_id": log["_id"]},
            {"$set": {"processed": True}}
        )

async def worker():
    while True:
        try:
            await asyncio.to_thread(process_pending_logs)
            await asyncio.sleep(2)
        except Exception as e:
            print("[!] Worker error:", e)
            await asyncio.sleep(5)


@app.get("/api/health")
def health():
    return {"status": "ok"}

@app.post("/api/chatbot/query")
async def chatbot_query(req: ChatRequest):
    try:
        parsed = parse_query(req.query)

        # ❌ UNKNOWN QUERY
        if parsed.get("intent") == "unknown":
            return {
                "success": False,
                "message": parsed.get("message", "I didn't understand your query.")
            }

        # ℹ️ INFO QUERY (future AI integration)
        if parsed.get("intent") == "info":
            return {
                "success": True,
                "type": "info",
                "message": f"Information about '{parsed.get('topic')}' will be available soon."
            }

        # 🔍 NORMAL SEARCH
        filters = parsed.get("filters", {})
        collection = parsed.get("collection", "network_logs")

        results = fetch_logs(db, filters, collection)

        return {
            "success": True,
            "filters": filters,
            "count": len(results),
            "results": results
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }