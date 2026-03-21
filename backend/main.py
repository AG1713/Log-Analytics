from fastapi import FastAPI, Request  # Added Request here
from ml_service import generate_attack_summary
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient       # Added for Database connection
import smtplib
from email.mime.text import MIMEText

app = FastAPI()

# --- CONFIGURATION ---
# Gmail Credentials (Use an App Password, not your regular password)
GMAIL_USER = "your_actual_email@gmail.com" 
GMAIL_APP_PASSWORD = "abcd efgh ijkl mnop" 
VICTIM_EMAIL = "target_recipient@example.com"

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173", 
        "http://localhost:5174",
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
config_db = client.siem_config

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
    msg['Subject'] = subject
    msg['From'] = GMAIL_USER
    msg['To'] = VICTIM_EMAIL

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
            server.sendmail(GMAIL_USER, VICTIM_EMAIL, msg.as_string())
        print(f"[+] Email alert sent to {VICTIM_EMAIL}")
    except Exception as e:
        print(f"[!] Email failed: {e}")

# --- NEW: DYNAMIC CONFIGURATION ENDPOINTS ---

@app.get("/api/config")
async def get_config():
    """Returns the current list of monitored paths to the Agent."""
    doc = config_db.settings.find_one({"type": "watch_config"})
    if not doc:
        # Default starting paths if database is empty
        return {"paths": ["/etc/nginx", "/var/www/html"]}
    return {"paths": doc["paths"]}

@app.post("/api/add_path")
async def add_path(request: Request):
    """Allows the Frontend to add a new file path to the SIEM."""
    data = await request.json()
    new_path = data.get("path")
    
    if not new_path:
        return {"status": "error", "message": "No path provided"}

    # $addToSet ensures the path is added only if it's not already there (prevents duplicates)
    """
    By using the $addToSet operator in MongoDB, you are telling the database: "Keep all the previous paths, and if this new path doesn't already exist in the list, add it."
    """
    config_db.settings.update_one(
        {"type": "watch_config"},
        {"$addToSet": {"paths": new_path}}, 
        upsert=True
    )
    
    print(f"[*] New path added to monitoring: {new_path}")
    return {"status": "success", "added": new_path}

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
    
    send_email_notification(
        alert_data.get("type", "FIM_ALERT"),
        alert_data.get("file", "Unknown"),
        alert_data.get("severity", "High")
    )

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
