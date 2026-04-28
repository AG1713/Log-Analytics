from datetime import datetime, timedelta, timezone
import re

# ---------------- PARSER ----------------
def parse_query(query: str):
    query = query.lower()

    filters = {}
    collection = "network_logs"
    intent = "unknown"

    # ---------------- ATTACK TYPES ----------------
    attack_map = {
        "dos": "DoS",
        "portscan": "Portscan",
        "bruteforce": "Bruteforce",
        "fuzzer": "Fuzzer",
        "backdoor": "Backdoor",
        "exploit": "Exploits",
        "recon": "Reconnaissance",
        "worm": "Worms"
    }

    for key, value in attack_map.items():
        if key in query:
            filters["attack_type"] = {"$regex": key, "$options": "i"}
            collection = "predictions"
            intent = "search"

    # ---------------- PREDICTION ----------------
    if "attack" in query:
        filters["prediction"] = "Attack"
        collection = "predictions"
        intent = "search"

    elif "normal" in query:
        filters["prediction"] = "Normal"
        collection = "predictions"
        intent = "search"

    # ---------------- SEVERITY ----------------
    if "high" in query:
        filters["severity"] = "high"
    elif "medium" in query:
        filters["severity"] = "medium"
    elif "low" in query:
        filters["severity"] = "low"

    # ---------------- TIME ----------------
    now = datetime.now(timezone.utc)

    minutes_match = re.search(r'last (\d+) minute', query)
    if minutes_match:
        filters["timestamp"] = {
            "$gte": now - timedelta(minutes=int(minutes_match.group(1)))
        }
        intent = "search"

    hours_match = re.search(r'last (\d+) hour', query)
    if hours_match:
        filters["timestamp"] = {
            "$gte": now - timedelta(hours=int(hours_match.group(1)))
        }
        intent = "search"

    days_match = re.search(r'last (\d+) day', query)
    if days_match:
        filters["timestamp"] = {
            "$gte": now - timedelta(days=int(days_match.group(1)))
        }
        intent = "search"

    # ---------------- GENERAL QUESTIONS ----------------
    if any(word in query for word in ["what is", "explain", "define"]):
        intent = "info"

    # ---------------- FALLBACK ----------------
    if intent == "unknown":
        return {
            "intent": "unknown",
            "message": "I didn’t understand your query. Try something like: 'show dos attacks last 1 hour'"
        }

    return {
        "intent": intent,
        "filters": filters,
        "collection": collection
    }


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