import os
from pymongo import MongoClient
from pymongo.errors import PyMongoError

MONGO_URI = os.getenv("MONGO_URI", "mongodb://mongodb:27018")
client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)

try:
    client.admin.command("ping")
    print(f"✅ MongoDB connected to {MONGO_URI}")
except PyMongoError as e:
    print("❌ MongoDB connection failed:", e)
    raise

db = client.siem_db
config_db = client.siem_config
fim_db = client.fim_integrity