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


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🚀 Starting background worker")
    task = asyncio.create_task(worker())
    yield
    task.cancel()


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
    allow_credentials=True,   # Added
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(dashboard_router)
app.include_router(fim_router)
app.include_router(network_logs_router)


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