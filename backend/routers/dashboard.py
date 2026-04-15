from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException
from pymongo.errors import PyMongoError

from database import db
from .fim import serialize

router = APIRouter(prefix="/api", tags=["Dashboard"])

NORMAL_LABEL = "Normal"


@router.get("/attack-summary-1")
def attack_summary():
    try:
        total_records = db.network_logs.count_documents({})
        total_attacks = db.predictions.count_documents({"attack": {"$ne": NORMAL_LABEL}})
        total_normal = db.predictions.count_documents({"attack": NORMAL_LABEL})

        attack_data = db.predictions.aggregate([
            {"$group": {"_id": "$attack", "count": {"$sum": 1}}}
        ])
        attack_distribution = {
            str(item["_id"]) if item["_id"] is not None else "Unknown": item["count"]
            for item in attack_data
        }

        severity_data = db.predictions.aggregate([
            {"$group": {"_id": "$severity", "count": {"$sum": 1}}}
        ])
        severity_distribution = {
            str(item["_id"]) if item["_id"] is not None else "Unknown": item["count"]
            for item in severity_data
        }

        proto_data = db.predictions.aggregate([
            {"$group": {"_id": "$proto", "count": {"$sum": 1}}}
        ])
        protocol_distribution = {
            str(item["_id"]) if item["_id"] is not None else "Unknown": item["count"]
            for item in proto_data
        }

        service_data = db.predictions.aggregate([
            {"$group": {"_id": "$service", "count": {"$sum": 1}}}
        ])
        service_distribution = {
            str(item["_id"]) if item["_id"] is not None else "Unknown": item["count"]
            for item in service_data
        }

        return {
            "total_records": total_records,
            "total_attacks": total_attacks,
            "total_normal": total_normal,
            "attack_distribution": attack_distribution,
            "severity_distribution": severity_distribution,
            "protocol_distribution": protocol_distribution,
            "service_distribution": service_distribution,
        }

    except PyMongoError as e:
        raise HTTPException(status_code=500, detail=f"MongoDB error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

@router.get("/attack-summary")
def attack_summary():
    try:
        # Existing logic
        total_records = db.network_logs.count_documents({})
        total_attacks = db.predictions.count_documents({"attack": {"$ne": NORMAL_LABEL}})
        total_normal = db.predictions.count_documents({"attack": NORMAL_LABEL})
        
        # --- NEW METRICS FOR STATCARDS ---
        # Get unique source IPs from network logs
        unique_ips = len(db.network_logs.distinct("src_ip"))
        
        # Get specific counts for your currently supported models
        dos_count = db.predictions.count_documents({"attack": "DoS"})
        # Assuming your label might be "Reconnaissance" or "Port Scan"
        port_scan_count = db.predictions.count_documents({"attack": {"$in": ["Port Scan", "Reconnaissance"]}})

        proto_data = db.predictions.aggregate([
            {"$group": {"_id": "$proto", "count": {"$sum": 1}}}
        ])
        protocol_distribution = {
            str(item["_id"]) if item["_id"] is not None else "Unknown": item["count"]
            for item in proto_data
        }

        service_data = db.predictions.aggregate([
            {"$group": {"_id": "$service", "count": {"$sum": 1}}}
        ])
        service_distribution = {
            str(item["_id"]) if item["_id"] is not None else "Unknown": item["count"]
            for item in service_data
        }

        return {
            "total_records": total_records,
            "total_attacks": total_attacks,
            "total_normal": total_normal,
            "unique_ips": unique_ips,               # New
            "dos_count": dos_count,                 # New
            "port_scan_count": port_scan_count,     # New
            "protocol_distribution": protocol_distribution,
            "service_distribution": service_distribution,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")
    # return {
    #     "total_records": 125430,
    #     "total_attacks": 1205,
    #     "total_normal": 124225,
    #     "unique_ips": 342,
    #     "dos_count": 850,
    #     "port_scan_count": 355,
    #     "attack_distribution": {
    #         "DoS": 850,
    #         "Port Scan": 355
    #     },
    #     "severity_distribution": {
    #         "critical": 0,
    #         "high": 850,
    #         "medium": 355,
    #         "low": 0
    #     },
    #     "protocol_distribution": {
    #         "TCP": 85000,
    #         "UDP": 30000,
    #         "ICMP": 10430
    #     },
    #     "service_distribution": {
    #         "HTTP": 45000,
    #         "HTTPS": 60000,
    #         "SSH": 15000,
    #         "FTP": 5430
    #     }
    # }


@router.get("/traffic-timeline")
def traffic_timeline(hours: int = 6):
    """Aggregates raw network logs by minute to show traffic volume over time"""
    try:
        # start_time is a native Python datetime object
        start_time = datetime.utcnow() - timedelta(hours=hours)
        
        pipeline = [
            # 1. Safely evaluate the string as a Date and compare it
            {
                "$match": {
                    "$expr": {
                        "$gte": [{"$toDate": "$timestamp"}, start_time]
                    }
                }
            },
            # 2. Group by date parts, parsing the string on the fly again
            {
                "$group": {
                    "_id": {
                        "y": {"$year": {"$toDate": "$timestamp"}},
                        "m": {"$month": {"$toDate": "$timestamp"}},
                        "d": {"$dayOfMonth": {"$toDate": "$timestamp"}},
                        "h": {"$hour": {"$toDate": "$timestamp"}},
                        "minute": {"$minute": {"$toDate": "$timestamp"}}
                    },
                    "volume": {"$sum": 1}
                }
            },
            # 3. Sort chronologically
            {"$sort": {"_id.y": 1, "_id.m": 1, "_id.d": 1, "_id.h": 1, "_id.minute": 1}}
        ]
        
        # Pointing to network_logs now!
        results = db.network_logs.aggregate(pipeline)
        
        # Format for frontend Recharts
        formatted_data = []
        for r in results:
            time_str = f"{r['_id']['h']:02d}:{r['_id']['minute']:02d}"
            formatted_data.append({
                "time": time_str,
                "traffic": r["volume"]
            })
            
        return formatted_data

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")
    # formatted_data = []
    # now = datetime.utcnow()
    
    # for i in range(60):
    #     # Create timestamps going back in time
    #     t = now - timedelta(minutes=(60 - i) * (hours * 60 // 60))
        
    #     # Base traffic volume with a little bit of noise
    #     base_traffic = 150 + (i * 7 % 40)
        
    #     # Fake a massive DoS spike right in the middle of the graph
    #     if 25 <= i <= 30:
    #         base_traffic += 1200 
            
    #     formatted_data.append({
    #         "time": f"{t.hour:02d}:{t.minute:02d}",
    #         "traffic": base_traffic
    #     })
        
    # return formatted_data

# You will also need two basic endpoints for the quick-triage lists:
@router.get("/recent-attacks")
def recent_attacks(limit: int = 5):
    # docs = db.predictions.find({"attack": {"$ne": NORMAL_LABEL}}).sort("timestamp", -1).limit(limit)
    # return list(docs) # Ensure _id and timestamps are serialized
    # Generates safe, JSON-serializable dictionaries

    # PLACEHOLDER: Do not remove unless you have real data to replace it with (the above commented code is not it).
    # This is used to test the frontend display of recent attacks before we have real data flowing in.
    now_iso = datetime.utcnow().isoformat()
    attacks = []
    
    for i in range(limit):
        is_dos = i % 2 == 0
        attacks.append({
            "_id": f"fake_attack_id_{i}",
            "src_ip": f"192.168.1.{100 + i}",
            "dst_ip": "10.0.0.5",
            "timestamp": now_iso,
            "severity": "high" if is_dos else "medium",
            "attack": "DoS" if is_dos else "Port Scan"
        })
        
    return attacks

@router.get("/recent-fim")
def recent_fim(hostname = None, limit: int = 5):
    query = {}
    if hostname:
        query["hostname"] = hostname
    alerts = list(db.alerts.find(query).sort("_id", -1).limit(limit)) # currently sorting with id since theres no timestamp field.
    return [serialize(a) for a in alerts]
    # now_iso = datetime.utcnow().isoformat()
    # fim_alerts = []
    
    # for i in range(limit):
    #     fim_alerts.append({
    #         "_id": f"fake_fim_id_{i}",
    #         "file_path": f"/etc/nginx/conf.d/site_{i}.conf" if i % 2 == 0 else f"/usr/bin/custom_script_{i}.sh",
    #         "hostname": "server-alpha",
    #         "timestamp": now_iso,
    #         "action": "MODIFIED" if i % 2 == 0 else "DELETED"
    #     })
        
    # return fim_alerts


@router.get("/live-attacks")
def live_attacks():
    try:
        count = db.predictions.count_documents({"attack": {"$ne": NORMAL_LABEL}})
        return {"live_attacks": count}
    except PyMongoError as e:
        raise HTTPException(status_code=500, detail=f"MongoDB error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")


@router.get("/attack-timeline")
def get_attack_timeline(hours: int = 6):
    try:
        time_threshold = datetime.now(timezone.utc) - timedelta(hours=hours)

        pipeline = [
            {"$match": {"timestamp": {"$gte": time_threshold}}},
            {
                "$group": {
                    "_id": {
                        "year": {"$year": "$timestamp"},
                        "month": {"$month": "$timestamp"},
                        "day": {"$dayOfMonth": "$timestamp"},
                        "hour": {"$hour": "$timestamp"},
                    },
                    "total_traffic": {"$sum": 1},
                    "attacks": {
                        "$sum": {
                            "$cond": [{"$ne": ["$attack", NORMAL_LABEL]}, 1, 0]
                        }
                    },
                    "normal": {
                        "$sum": {
                            "$cond": [{"$eq": ["$attack", NORMAL_LABEL]}, 1, 0]
                        }
                    },
                }
            },
            {
                "$sort": {
                    "_id.year": 1,
                    "_id.month": 1,
                    "_id.day": 1,
                    "_id.hour": 1,
                }
            },
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

    except PyMongoError as e:
        raise HTTPException(status_code=500, detail=f"MongoDB error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")