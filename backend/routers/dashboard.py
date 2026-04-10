from datetime import datetime, timedelta

from fastapi import APIRouter

from database import db

router = APIRouter(prefix="/api", tags=["Dashboard"])


@router.get("/attack-summary")
def attack_summary():
    total_records = db.network_logs.count_documents({})
    total_attacks = db.predictions.count_documents({"attack": {"$ne": "BENIGN"}})
    total_normal = db.predictions.count_documents({"attack": "BENIGN"})

    attack_data = db.predictions.aggregate([
        {"$group": {"_id": "$attack", "count": {"$sum": 1}}}
    ])
    attack_distribution = {item["_id"]: item["count"] for item in attack_data}

    severity_data = db.predictions.aggregate([
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}}
    ])
    severity_distribution = {item["_id"]: item["count"] for item in severity_data}

    proto_data = db.predictions.aggregate([
        {"$group": {"_id": "$proto", "count": {"$sum": 1}}}
    ])
    protocol_distribution = {item["_id"]: item["count"] for item in proto_data}

    service_data = db.predictions.aggregate([
        {"$group": {"_id": "$service", "count": {"$sum": 1}}}
    ])
    service_distribution = {item["_id"]: item["count"] for item in service_data}

    return {
        "total_records": total_records,
        "total_attacks": total_attacks,
        "total_normal": total_normal,
        "attack_distribution": attack_distribution,
        "severity_distribution": severity_distribution,
        "protocol_distribution": protocol_distribution,
        "service_distribution": service_distribution,
    }


@router.get("/live-attacks")
def live_attacks():
    count = db.predictions.count_documents({"attack": {"$ne": "BENIGN"}})
    return {"live_attacks": count}


@router.get("/attack-timeline")
def get_attack_timeline(hours: int = 6):
    time_threshold = datetime.utcnow() - timedelta(hours=hours)

    pipeline = [
        {"$match": {"received_at": {"$gte": time_threshold}}},
        {"$group": {
            "_id": {
                "year": {"$year": "$received_at"},
                "month": {"$month": "$received_at"},
                "day": {"$dayOfMonth": "$received_at"},
                "hour": {"$hour": "$received_at"},
            },
            "total_traffic": {"$sum": 1},
            "attacks": {
                "$sum": {"$cond": [{"$ne": ["$attack", "BENIGN"]}, 1, 0]}
            },
            "normal": {
                "$sum": {"$cond": [{"$eq": ["$attack", "BENIGN"]}, 1, 0]}
            },
        }},
        {"$sort": {"_id.year": 1, "_id.month": 1, "_id.day": 1, "_id.hour": 1}},
    ]

    results = list(db.predictions.aggregate(pipeline))

    formatted_data = []
    for res in results:
        dt_str = (
            f"{res['_id']['year']}-{res['_id']['month']:02d}-"
            f"{res['_id']['day']:02d}T{res['_id']['hour']:02d}:00:00Z"
        )
        formatted_data.append({
            "timestamp": dt_str,
            "total_traffic": res["total_traffic"],
            "attacks": res["attacks"],
            "normal": res["normal"],
        })

    return formatted_data