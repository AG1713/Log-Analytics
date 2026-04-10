from pymongo import MongoClient

# Centralized MongoDB connection
client = MongoClient("mongodb://172.17.0.1:27018/")

# Shared DB handles
db = client.siem_db
config_db = client.siem_config
fim_db = client.fim_integrity
