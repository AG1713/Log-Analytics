from datetime import datetime, timedelta, timezone
import re

# ---------------- PARSER ----------------
def parse_query(query: str):
    query = query.lower()

    filters = {}
    collection = "network_logs"
    # Attack types
    attack_types = ["dos", "portscan", "bruteforce", "fuzzer"]
    for attack in attack_types:
        if attack in query:
            filters["attack_type"] = {"$regex": attack, "$options": "i"}
            collection = "predictions"
    # Prediction
    if "attack" in query:
        filters["prediction"] = "Attack"
        collection = "predictions"
    elif "normal" in query:
        filters["prediction"] = "Normal"
        collection = "predictions"

    # Severity
    if "high" in query:
        filters["severity"] = "high"
    elif "medium" in query:
        filters["severity"] = "medium"
    elif "low" in query:
        filters["severity"] = "low"

    # Time parsing
    now = datetime.now(timezone.utc)

    minutes_match = re.search(r'last (\d+) minute', query)
    if minutes_match:
        mins = int(minutes_match.group(1))
        filters["timestamp"] = {"$gte": now - timedelta(minutes=mins)}

    hours_match = re.search(r'last (\d+) hour', query)
    if hours_match:
        hrs = int(hours_match.group(1))
        filters["timestamp"] = {"$gte": now - timedelta(hours=hrs)}

    days_match = re.search(r'last (\d+) day', query)
    if days_match:
        days = int(days_match.group(1))
        filters["timestamp"] = {"$gte": now - timedelta(days=days)}

    return filters, collection


# ---------------- FETCH FROM DB ----------------
def fetch_logs(db, filters, collection_name):
    collection = db[collection_name]

    results = collection.find(filters).limit(50)

    formatted = []

    for r in results:
        print("FULL DOC:", r)  # DEBUG

        ts = r.get("timestamp")

        formatted.append({
            "time": ts.isoformat() if ts else "N/A",
            "attack_type": r.get("attack_type"),
            "prediction": r.get("prediction"),
            "severity": r.get("severity"),
            "src_ip": r.get("src_ip"),
            "dst_ip": r.get("dst_ip"),
        })

    return formatted