import os
from datetime import datetime, timezone

os.environ["LOKY_MAX_CPU_COUNT"] = "4"

from ml_service import predict
from database import db  # Use shared db, no separate client

network_logs_col = db["network_logs"]
predictions_col = db["predictions"]
alerts_col = db["attack_alerts"]

SEVERITY_MAP = {
    "DoS": "high",
    "Exploits": "high",
    "Backdoor": "high",
    "Shellcode": "high",
    "Worms": "high",
    "Analysis": "medium",
    "Fuzzers": "medium",
    "Reconnaissance": "medium",
    "Generic": "medium",
    "suspicious_unknown": "high",
    "None": "low",
}


def predict_log(log):
    try:
        result = predict(log)

        if result is None:
            print("⏭️ Skipped log")
            if log.get("_id") is not None:
                network_logs_col.update_one(
                    {"_id": log["_id"]},
                    {
                        "$set": {
                            "prediction": "Skipped",
                            "attack_type": "None",
                            "confidence": 0.0,
                            "type_confidence": 0.0,
                            "anomaly": False,
                            "severity": "low",
                            "processed": True,
                            "processed_at": datetime.now(timezone.utc),
                        }
                    },
                )
            return

        prediction = result.get("prediction", "Unknown")
        attack_type = result.get("attack_type", "None")
        confidence = float(result.get("confidence", 0.0))
        type_confidence = float(result.get("type_confidence", 0.0))
        anomaly = bool(result.get("anomaly", False))
        severity = result.get("severity", SEVERITY_MAP.get(attack_type, "low"))

        record = {
            "raw_log_id": log.get("_id"),
            "timestamp": datetime.now(timezone.utc),
            "hostname": log.get("hostname"),
            "prediction": prediction,
            "attack": prediction,
            "attack_type": attack_type,
            "confidence": round(confidence, 4),
            "type_confidence": round(type_confidence, 4),
            "anomaly": anomaly,
            "severity": severity,
            "src_ip": log.get("src_ip"),
            "src_port": log.get("src_port"),
            "dst_ip": log.get("dst_ip", "unknown"),
            "dst_port": log.get("dst_port"),
            "proto": log.get("proto", "unknown"),
            "service": log.get("service", "unknown"),
            "state": log.get("state", "unknown"),
            "dur": log.get("dur", 0),
            "spkts": log.get("spkts", 0),
            "dpkts": log.get("dpkts", 0),
            "sbytes": log.get("sbytes", 0),
            "dbytes": log.get("dbytes", 0),
        }

        predictions_col.insert_one(record)

        if attack_type != "None" and confidence >= 0.50:
            alerts_col.update_one(
                {
                    # The Aggregation Key
                    "src_ip": log.get("src_ip"),
                    "dst_ip": log.get("dst_ip", "unknown"),
                    "attack_type": attack_type,
                    "status": "Active"
                },
                {
                    # Increment the count of how many times we've seen this attack
                    "$inc": {"event_count": 1},
                    # Update the last seen time
                    "$set": {
                        "last_seen": datetime.now(timezone.utc),
                        "severity": severity
                    },
                    # Only set these fields if this is the very first log triggering the alert
                    "$setOnInsert": {
                        "first_seen": datetime.now(timezone.utc),
                        "hostname": log.get("hostname"),
                        "avg_confidence": round(confidence, 4) 
                    }
                },
                upsert=True
            )

        if log.get("_id") is not None:
            network_logs_col.update_one(
                {"_id": log["_id"]},
                {
                    "$set": {
                        # ONLY update the state flags
                        "processed": True,
                        "processed_at": datetime.now(timezone.utc),
                    }
                },
            )

        if attack_type != "None":
            print(f"🚨 {attack_type:<20} ({confidence:.2%})")
        else:
            print(f"✅ NORMAL ({confidence:.2%})")

    except Exception as e:
        print("❌ ML Error:", e)
        if log.get("_id") is not None:
            network_logs_col.update_one(
                {"_id": log["_id"]},
                {
                    "$set": {
                        "processed": True,
                        "processed_at": datetime.now(timezone.utc),
                        "ml_error": str(e),
                    }
                },
            )


def process_unprocessed_logs(limit=100):
    try:
        cursor = network_logs_col.find({"processed": {"$ne": True}}).limit(limit)
        count = 0
        for log in cursor:
            predict_log(log)
            count += 1
        print(f"Processed {count} logs")
    except Exception as e:
        print("❌ Worker loop error:", e)


if __name__ == "__main__":
    process_unprocessed_logs()