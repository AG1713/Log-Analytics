from fastapi import FastAPI, Request  # Added Request here
from ml_service import generate_attack_summary
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient       # Added for Database connection

app = FastAPI()


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173", 
        "http://127.0.0.1:5173",
        "http://172.17.0.4:5173",
        "http://172.17.0.1:5173"
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize the connection once when the app starts
client = MongoClient("mongodb://172.17.0.1:27017/")
db = client.siem_db

@app.get("/attack_summary")
def attack_summary():
    return generate_attack_summary()

# Before running backend:
#   1) Make sure to create a venv, if not already, command:
#       python -m venv venv
#   2) Make sure to activate the venv, if not already, command:
#       venv\Scripts\activate
#   3) Make sure to install requirements.txt, if not already, command:
#       pip install -r requirements.txt

# To run this api, command: uvicorn main:app --reload

@app.post("/api/alerts")
async def receive_alert(request: Request):
    # 1. Parse the JSON sent by the agent
    alert_data = await request.json()
    
    # 2. Connect to your MongoDB (Make sure your MongoClient is accessible here)
    # If you haven't defined 'db' globally, you'll need to do it here or inside the function
    # client = MongoClient("mongodb://172.17.0.1:27017/")
    # db = client.siem_db
    
    # 3. Insert into the 'alerts' collection
    result = db.alerts.insert_one(alert_data)
    
    print(f"[+] FIM Alert Received and Saved: {result.inserted_id}")
    return {"status": "success", "id": str(result.inserted_id)}

@app.get("/api/alerts")
async def get_alerts():
    """Endpoint for the Frontend to fetch all security alerts."""
    # Fetch all alerts, sorted by newest first
    alerts = list(db.alerts.find().sort("_id", -1))
    
    # Convert MongoDB ObjectIds to strings so they are JSON serializable
    for alert in alerts:
        alert["_id"] = str(alert["_id"])
        
    return alerts
