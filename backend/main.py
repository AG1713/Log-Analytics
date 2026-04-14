print("--- 1. Starting Python ---", flush=True)
from fastapi import FastAPI
print("--- 2. Imported FastAPI ---", flush=True)
from fastapi.middleware.cors import CORSMiddleware
import asyncio
from contextlib import asynccontextmanager
from ml_worker import predict_log
print("--- 3. Imported ML Worker (Did the model load?) ---", flush=True)
from database import db
print("--- 4. Imported DB ---", flush=True)
from routers.dashboard import router as dashboard_router
from routers.fim import router as fim_router
from routers.network_logs import router as network_logs_router

# ──────────────────────────────────────────────────────────────────────────────
# LIFESPAN & WORKER
# ──────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🚀 Starting background worker")
    task = asyncio.create_task(worker())
    yield
    task.cancel()

async def worker():
    """Background loop to process logs every 2 seconds."""
    while True:
        try:
            # We run the synchronous DB processing in a separate thread 
            # to keep the FastAPI event loop non-blocking.
            await asyncio.to_thread(process_pending_logs)
            await asyncio.sleep(2)
        except Exception as e:
            print("[!] Worker loop error:", e)
            await asyncio.sleep(5)

# ──────────────────────────────────────────────────────────────────────────────
# APP SETUP
# ──────────────────────────────────────────────────────────────────────────────

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5173",
        "http://172.17.0.4:5173",
        "http://172.17.0.1:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(dashboard_router)
app.include_router(fim_router)
app.include_router(network_logs_router)

# ──────────────────────────────────────────────────────────────────────────────
# PROCESSING LOGIC
# ──────────────────────────────────────────────────────────────────────────────

def process_pending_logs():
    """
    Fetches unprocessed logs and delegates to ml_worker.
    The ml_worker.predict_log now handles the complex Normal/Attack 
    filtering and the final MongoDB update.
    """
    # Only fetch logs not yet processed
    logs = list(db.network_logs.find({
        "processed": {"$ne": True}
    }).limit(20))
    
    if not logs:
        return

    for log in logs:
        # We call the worker logic. If an error occurs inside predict_log,
        # it is handled there to avoid crashing this loop.
        predict_log(log)

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

# ──────────────────────────────────────────────────────────────────────────────
# ENDPOINTS
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/check-duplicates")
async def get_duplicates():
    return find_duplicate_hostnames()

@app.get("/api/health")
def health():
    return {"status": "ok"}