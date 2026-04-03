import joblib
from pymongo import MongoClient
import numpy as np
import time
from collections import defaultdict

MONGO_URL = "mongodb://localhost:27017"

# ============================
# 📦 LOAD MODELS + ENCODERS
# ============================
try:
    binary_model  = joblib.load("models/binary_model.pkl")
    stage1_model  = joblib.load("models/stage1_model.pkl")
    stage2_model  = joblib.load("models/stage2_model.pkl")
    stage3_model  = joblib.load("models/stage3_model.pkl")

    proto_enc   = joblib.load("models/proto_enc.pkl")
    service_enc = joblib.load("models/service_enc.pkl")

    stage1_enc = joblib.load("models/stage1_enc.pkl")
    dos_enc    = joblib.load("models/dos_enc.pkl")
    rare_enc   = joblib.load("models/rare_enc.pkl")

    scaler = joblib.load("models/scaler.pkl")

    print("✅ ML models loaded successfully")

except Exception as e:
    print(f"[!] Model loading failed: {e}")
    binary_model = stage1_model = stage2_model = stage3_model = None
    proto_enc = service_enc = None
    stage1_enc = dos_enc = rare_enc = scaler = None


# ============================
# ⚠️ SEVERITY MAP
# ============================
SEVERITY_MAP = {
    "DoS": "high", "Exploits": "high", "Backdoor": "high",
    "Shellcode": "high", "Worms": "high",
    "Analysis": "medium", "Fuzzers": "medium",
    "Reconnaissance": "medium", "Generic": "medium",
    "suspicious_unknown": "high"
}

# ============================
# 🧠 BASELINE + RATE LIMIT
# ============================
BASELINE_IPS = set()
BASELINE_SERVICES = set()
LAST_SEEN = defaultdict(float)

# ============================
# 🔧 SAFE ENCODING (FIXED)
# ============================
def safe_transform(encoder, value):
    try:
        val_str = str(value)
        if val_str in encoder.classes_:
            return encoder.transform([val_str])[0]
        else:
            return encoder.transform([encoder.classes_[0]])[0]
    except:
        return encoder.transform([encoder.classes_[0]])[0]


# ============================
# 🔧 PREPROCESS + FILTER
# ============================
def preprocess(log):
    try:
        # 🚫 HARD FILTER
        if log.get("src_ip") in ["127.0.0.1", "0.0.0.0"]:
            return None

        if float(log.get("spkts", 0)) == 0 and float(log.get("dpkts", 0)) == 0:
            return None

        if float(log.get("sbytes", 0)) < 50 and float(log.get("dbytes", 0)) < 50:
            return None

        if log.get("proto") not in ["tcp", "udp"]:
            return None

        proto   = safe_transform(proto_enc,   log.get("proto", "tcp"))
        service = safe_transform(service_enc, log.get("service", "other"))

        dur    = float(log.get("dur", 0))
        spkts  = float(log.get("spkts", 0))
        dpkts  = float(log.get("dpkts", 0))
        sbytes = float(log.get("sbytes", 0))
        dbytes = float(log.get("dbytes", 0))
        rate   = float(log.get("rate", 0))
        sttl   = float(log.get("sttl", 0))
        dttl   = float(log.get("dttl", 0))

        byte_ratio   = sbytes / (dbytes + 1)
        packet_ratio = spkts / (dpkts + 1)
        ttl_diff     = sttl - dttl

        raw = np.array([[ 
            dur, proto, service, spkts, dpkts,
            sbytes, dbytes, rate, sttl, dttl,
            byte_ratio, packet_ratio, ttl_diff
        ]])

        return scaler.transform(raw) if scaler is not None else raw

    except Exception as e:
        print(f"[!] Preprocessing error: {e}")
        return None


# ============================
# 🔮 MULTI-STAGE ATTACK TYPE
# ============================
def predict_attack_type(features_scaled):

    dos_like_idx = stage1_enc.transform(["dos_like"])[0]
    rare_idx     = stage1_enc.transform(["rare"])[0]

    s1_pred = stage1_model.predict(features_scaled)[0]

    if s1_pred == dos_like_idx:
        pred = stage2_model.predict(features_scaled)[0]
        return dos_enc.classes_[pred]

    elif s1_pred == rare_idx:
        probs = stage3_model.predict_proba(features_scaled)[0]

        if np.max(probs) < 0.6:
            return "suspicious_unknown"

        return rare_enc.classes_[np.argmax(probs)]

    else:
        return stage1_enc.classes_[s1_pred]


# ============================
# 🚀 FINAL PREDICT FUNCTION
# ============================
def predict(log):

    if binary_model is None:
        return {
            "prediction": "Unknown",
            "attack_type": "Model Not Loaded",
            "confidence": 0.0,
            "anomaly": False,
            "severity": "unknown"
        }

    try:
        src_ip = log.get("src_ip")
        service = log.get("service")

        # 🧠 BASELINE
        BASELINE_IPS.add(src_ip)
        BASELINE_SERVICES.add(service)

        if src_ip in BASELINE_IPS and service in BASELINE_SERVICES:
            if float(log.get("spkts", 0)) < 5:
                return None

        # ⏱️ RATE LIMIT
        key = f"{src_ip}-{service}"
        now = time.time()

        if now - LAST_SEEN[key] < 5:
            return None

        LAST_SEEN[key] = now

        features = preprocess(log)

        if features is None:
            return None

        probs = binary_model.predict_proba(features)[0]
        attack_prob = float(probs[1])
        benign_prob = float(probs[0])

        # 🔥 STRICT DECISION
        if attack_prob >= 0.85:
            attack_label = predict_attack_type(features)

            result = {
                "prediction": "Attack",
                "attack_type": attack_label,
                "confidence": round(attack_prob, 4),
                "anomaly": True,
                "severity": SEVERITY_MAP.get(attack_label, "medium")
            }

        else:
            result = {
                "prediction": "Normal",
                "attack_type": "None",
                "confidence": round(benign_prob, 4),
                "anomaly": False,
                "severity": "normal"
            }

        # 🧼 CLEAN MODE
        if float(log.get("spkts", 0)) < 3 and float(log.get("sbytes", 0)) < 200:
            result["prediction"] = "Normal"
            result["attack_type"] = "None"
            result["anomaly"] = False

        return result

    except Exception as e:
        print(f"[!] Prediction error: {e}")
        return {
            "prediction": "Error",
            "attack_type": str(e),
            "confidence": 0.0,
            "anomaly": False,
            "severity": "unknown"
        }


# ============================
# 📊 ATTACK SUMMARY (REAL-TIME FIX)
# ============================
def generate_attack_summary():
    try:
        client = MongoClient(MONGO_URL)
        db = client.siem_db

        from datetime import datetime, timedelta
        last_5_min = datetime.utcnow() - timedelta(minutes=5)

        pipeline = [
            {
                "$match": {
                    "prediction": "Attack",
                    "timestamp": {"$gte": last_5_min}
                }
            },
            {
                "$group": {
                    "_id": "$attack_type",
                    "count": {"$sum": 1},
                    "avg_confidence": {"$avg": "$confidence"}
                }
            },
            {"$sort": {"count": -1}}
        ]

        results = list(db.network_logs.aggregate(pipeline))

        return [
            {
                "attack_type": r["_id"],
                "count": r["count"],
                "avg_confidence": round(r.get("avg_confidence", 0), 4)
            }
            for r in results
        ]

    except Exception as e:
        return {"error": str(e)}