# import joblib
# from pymongo import MongoClient
# from datetime import datetime
# import numpy as np
# import os
# import time
# from collections import defaultdict

# # Fix CPU warning
# os.environ["LOKY_MAX_CPU_COUNT"] = "4"

# # ============================
# # 🔧 DB CONNECTION
# # ============================
# client = MongoClient("mongodb://localhost:27017/")
# db = client["siem_db"]

# # ============================
# # 📦 LOAD MODELS
# # ============================
# binary_model  = joblib.load("binary_model.pkl")
# stage1_model  = joblib.load("stage1_model.pkl")
# stage2_model  = joblib.load("stage2_model.pkl")
# stage3_model  = joblib.load("stage3_model.pkl")

# proto_enc   = joblib.load("proto_enc.pkl")
# service_enc = joblib.load("service_enc.pkl")

# stage1_enc = joblib.load("stage1_enc.pkl")
# dos_enc    = joblib.load("dos_enc.pkl")
# rare_enc   = joblib.load("rare_enc.pkl")

# scaler = joblib.load("scaler.pkl")

# # ============================
# # ⚠️ SEVERITY MAP
# # ============================
# SEVERITY_MAP = {
#     "DoS": "high", "Exploits": "high",
#     "Backdoor": "high", "Shellcode": "high",
#     "Worms": "high",
#     "Analysis": "medium", "Fuzzers": "medium",
#     "Reconnaissance": "medium", "Generic": "medium",
#     "suspicious_unknown": "high"
# }

# # ============================
# # 🧠 BASELINE + RATE LIMIT
# # ============================
# BASELINE = defaultdict(int)
# LAST_SEEN = defaultdict(float)

# # ============================
# # 🔧 SAFE ENCODING
# # ============================
# def safe_encode(encoder, value):
#     try:
#         val = str(value)
#         if val in encoder.classes_:
#             return encoder.transform([val])[0]
#         return encoder.transform([encoder.classes_[0]])[0]
#     except:
#         return 0

# # ============================
# # 🔧 PREPROCESS
# # ============================
# def preprocess(log):
#     try:
#         if log.get("src_ip") in ["127.0.0.1", "0.0.0.0"]:
#             return None

#         if log.get("proto") not in ["tcp", "udp"]:
#             return None

#         spkts = float(log.get("spkts", 0))
#         sbytes = float(log.get("sbytes", 0))

#         if spkts < 3 or sbytes < 100:
#             return None

#         proto   = safe_encode(proto_enc, log.get("proto", "tcp"))
#         service = safe_encode(service_enc, log.get("service", "other"))

#         dur    = float(log.get("dur", 0))
#         dpkts  = float(log.get("dpkts", 0))
#         dbytes = float(log.get("dbytes", 0))
#         rate   = float(log.get("rate", 0))
#         sttl   = float(log.get("sttl", 0))
#         dttl   = float(log.get("dttl", 0))

#         byte_ratio   = sbytes / (dbytes + 1)
#         packet_ratio = spkts / (dpkts + 1)
#         ttl_diff     = sttl - dttl

#         raw = np.array([[ 
#             dur, proto, service, spkts, dpkts,
#             sbytes, dbytes, rate, sttl, dttl,
#             byte_ratio, packet_ratio, ttl_diff
#         ]])

#         return scaler.transform(raw)

#     except Exception as e:
#         print("[!] Preprocess error:", e)
#         return None

# # ============================
# # 🔮 ATTACK TYPE
# # ============================
# def predict_attack_type(features):

#     s1 = stage1_model.predict(features)[0]

#     dos_idx = stage1_enc.transform(["dos_like"])[0]
#     rare_idx = stage1_enc.transform(["rare"])[0]

#     if s1 == dos_idx:
#         pred = stage2_model.predict(features)[0]
#         return dos_enc.classes_[pred]

#     elif s1 == rare_idx:
#         probs = stage3_model.predict_proba(features)[0]

#         if np.max(probs) < 0.6:
#             return "suspicious_unknown"

#         return rare_enc.classes_[np.argmax(probs)]

#     return stage1_enc.classes_[s1]

# # ============================
# # 🚀 MAIN FUNCTION
# # ============================
# def predict_log(log):
#     try:
#         src_ip = log.get("src_ip")
#         service = log.get("service")

#         key = f"{src_ip}-{service}"

#         # ============================
#         # ⏱️ RATE LIMIT
#         # ============================
#         now = time.time()
#         # if now - LAST_SEEN[key] < 3:
#         #     return
#         LAST_SEEN[key] = now

#         # ============================
#         # 🧠 BASELINE LEARNING
#         # ============================
#         BASELINE[key] += 1

#         # Allow baseline to stabilize
#         # if BASELINE[key] < 5:
#         #     return

#         # ============================
#         # PREPROCESS
#         # ============================
#         features = preprocess(log)
#         if features is None:
#             return

#         # ============================
#         # 🔮 BINARY PREDICTION
#         # ============================
#         probs = binary_model.predict_proba(features)[0]
#         attack_prob = float(probs[1])
#         benign_prob = float(probs[0])

#         # ============================
#         # 🔥 STRICT LOGIC
#         # ============================
#         if attack_prob >= 0.85:
#             attack_type = predict_attack_type(features)

#             # 🚨 HARD DoS PROTECTION
#             if attack_type == "DoS" and attack_prob < 0.95:
#                 attack = "BENIGN"
#                 attack_type = "None"
#             else:
#                 attack = attack_type

#             confidence = round(attack_prob, 4)

#         else:
#             attack = "BENIGN"
#             attack_type = "None"
#             confidence = round(benign_prob, 4)

#         # ============================
#         # 💾 STORE
#         # ============================
#         record = {
#             "timestamp": datetime.utcnow(),
#             "attack": attack,
#             "attack_type": attack_type,
#             "confidence": confidence,
#             "severity": SEVERITY_MAP.get(attack_type, "normal"),
#             "src_ip": src_ip,
#             "dst_ip": log.get("dst_ip", "unknown"),
#             "proto": log.get("proto", "unknown"),
#             "service": service,
#         }

#         db.predictions.insert_one(record)

#         db.attack_summary.update_one(
#             {"attack": attack},
#             {"$inc": {"count": 1}},
#             upsert=True
#         )

#         # ============================
#         # 🖥️ OUTPUT
#         # ============================
#         if attack == "BENIGN":
#             print(f"✅ BENIGN ({confidence:.2%})")
#         else:
#             print(f"🚨 {attack:<20} ({confidence:.2%} | {src_ip})")

#     except Exception as e:
#         print("❌ ML Error:", e)

import joblib
from pymongo import MongoClient
from datetime import datetime
import numpy as np
import os

# Fix CPU warning
os.environ["LOKY_MAX_CPU_COUNT"] = "4"

# ============================
# 🔧 DB CONNECTION
# ============================
client = MongoClient("mongodb://172.17.0.1:27018/")
db = client["siem_db"]

# ============================
# 📦 LOAD MODELS
# ============================
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

# ============================
# ⚠️ SEVERITY MAP
# ============================
SEVERITY_MAP = {
    "DoS": "high", "Exploits": "high",
    "Backdoor": "high", "Shellcode": "high",
    "Worms": "high",
    "Analysis": "medium", "Fuzzers": "medium",
    "Reconnaissance": "medium", "Generic": "medium",
    "suspicious_unknown": "high"
}

# ============================
# 🔧 SAFE ENCODING
# ============================
def safe_encode(encoder, value):
    try:
        val = str(value)
        if val in encoder.classes_:
            return encoder.transform([val])[0]
        return encoder.transform([encoder.classes_[0]])[0]
    except:
        return 0

# ============================
# 🔧 PREPROCESS
# ============================
def preprocess(log):
    try:
        # Basic filtering (relaxed for demo)
        if log.get("src_ip") in ["127.0.0.1", "0.0.0.0"]:
            return None

        proto   = safe_encode(proto_enc, log.get("proto", "tcp"))
        service = safe_encode(service_enc, log.get("service", "other"))

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

        return scaler.transform(raw)

    except Exception as e:
        print("[!] Preprocess error:", e)
        return None

# ============================
# 🔮 ATTACK TYPE
# ============================
def predict_attack_type(features):

    s1 = stage1_model.predict(features)[0]

    dos_idx = stage1_enc.transform(["dos_like"])[0]
    rare_idx = stage1_enc.transform(["rare"])[0]

    if s1 == dos_idx:
        pred = stage2_model.predict(features)[0]
        return dos_enc.classes_[pred]

    elif s1 == rare_idx:
        probs = stage3_model.predict_proba(features)[0]

        if np.max(probs) < 0.6:
            return "suspicious_unknown"

        return rare_enc.classes_[np.argmax(probs)]

    return stage1_enc.classes_[s1]

# ============================
# 🚀 MAIN FUNCTION
# ============================
def predict_log(log):
    try:
        features = preprocess(log)
        if features is None:
            return

        # ============================
        # 🔮 BINARY PREDICTION
        # ============================
        probs = binary_model.predict_proba(features)[0]
        attack_prob = float(probs[1])
        benign_prob = float(probs[0])

        # ============================
        # 🔥 SIMPLE DEMO LOGIC
        # ============================
        if attack_prob >= 0.6:
            attack_type = predict_attack_type(features)
            attack = attack_type
            confidence = round(attack_prob, 4)
        else:
            attack = "BENIGN"
            attack_type = "None"
            confidence = round(benign_prob, 4)

        # ============================
        # 💾 STORE PREDICTION
        # ============================
        record = {
            "timestamp": datetime.utcnow(),
            "hostname": log.get("hostname"),
            "attack": attack,
            "attack_type": attack_type,
            "confidence": confidence,
            "severity": SEVERITY_MAP.get(attack_type, "normal"),
            "src_ip": log.get("src_ip"),
            "dst_ip": log.get("dst_ip", "unknown"),
            "proto": log.get("proto", "unknown"),
            "service": log.get("service", "unknown"),
        }

        db.predictions.insert_one(record)

        # ============================
        # 🖥️ OUTPUT
        # ============================
        if attack == "BENIGN":
            print(f"✅ BENIGN ({confidence:.2%})")
        else:
            print(f"🚨 {attack:<20} ({confidence:.2%})")

    except Exception as e:
        print("❌ ML Error:", e)