from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException
from pymongo.errors import PyMongoError

from database import db
from .fim import serialize

router = APIRouter(prefix="/api", tags=["Dashboard"])

NORMAL_LABEL = "Normal"

@router.get("/attack-summary")
def attack_summary():
    try:
        # Existing logic
        total_records = db.network_logs.count_documents({})
        total_attacks = db.predictions.count_documents({"attack": {"$ne": NORMAL_LABEL}})
        total_normal = db.predictions.count_documents({"attack": NORMAL_LABEL})
        
        # Get unique source IPs from network logs
        unique_ips = len(db.network_logs.distinct("src_ip"))
        
        # Get specific counts for your currently supported models
        dos_count = db.predictions.count_documents({"attack_type": "DoS"})
        # Assuming your label might be "Reconnaissance" or "Port Scan"
        port_scan_count = db.predictions.count_documents({"attack_type": {"$in": ["Port Scan", "Reconnaissance"]}})

        proto_data = db.network_logs.aggregate([
            {"$group": {"_id": "$proto", "count": {"$sum": 1}}}
        ])
        protocol_distribution = {
            str(item["_id"]) if item["_id"] is not None else "Unknown": item["count"]
            for item in proto_data
        }

        service_data = db.network_logs.aggregate([
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
                        "y": {"$year": "$timestamp"},
                        "m": {"$month": "$timestamp"},
                        "d": {"$dayOfMonth": "$timestamp"},
                        "h": {"$hour": "$timestamp"},
                        "minute": {"$minute": "$timestamp"}
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

@router.get("/recent-attacks")
def recent_attacks(hostname = None, limit: int = 5):
    query = {"is_archived": {"$ne": True}}
    query["event_count"] = {"$gt": 10}
    if hostname:
        query["hostname"] = hostname
    alerts = list(db.attack_alerts.find(query).sort("last_seen", -1).limit(limit))
    return [serialize(a) for a in alerts]

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


@router.get("/analysis-summary")
def analysis_summary():
    try:
        # 1. Total flagged attacks (everything EXCEPT normal/benign)
        total_attacks = db.predictions.count_documents({"attack": {"$nin": [NORMAL_LABEL, "BENIGN"]}})

        # 2. Specific KPI counts
        dos_count = db.predictions.count_documents({"attack_type": "DoS"})
        port_scan_count = db.predictions.count_documents({"attack_type": {"$in": ["Port Scan", "Reconnaissance"]}})

        # 3. Data for the "Attack Signatures" Pie Chart
        pipeline = [
            # Only group actual attacks
            {"$match": {"attack": {"$nin": [NORMAL_LABEL, "BENIGN"]}}},
            # Count them up
            {"$group": {"_id": "$attack_type", "count": {"$sum": 1}}}
        ]
        attack_data = db.predictions.aggregate(pipeline)

        # Format it cleanly as a dictionary for the frontend
        attack_distribution = {
            str(item["_id"]) if item["_id"] is not None else "Unknown": item["count"]
            for item in attack_data
        }

        active_investigations = db.network_logs.count_documents({}) - db.predictions.count_documents({})

        return {
            "total_attacks": total_attacks,
            "dos_count": dos_count,
            "port_scan_count": port_scan_count,
            "active_investigations": active_investigations,
            "attack_distribution": attack_distribution
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

@router.get("/attack-timeline")
def attack_timeline(hours: int = 6):
    """Aggregates predictions by minute, splitting counts by attack type"""
    try:
        start_time = datetime.utcnow() - timedelta(hours=hours)
        
        # Note: Since we verified your predictions collection uses native ISODates, 
        # we don't need the $toDate string-parsing trick here!
        pipeline = [
            {"$match": {"timestamp": {"$gte": start_time}}},
            {
                "$group": {
                    "_id": {
                        "y": {"$year": "$timestamp"},
                        "m": {"$month": "$timestamp"},
                        "d": {"$dayOfMonth": "$timestamp"},
                        "h": {"$hour": "$timestamp"},
                        "minute": {"$minute": "$timestamp"}
                    },
                    # Count specific attack types
                    "dos_count": {
                        "$sum": {"$cond": [{"$eq": ["$attack_type", "DoS"]}, 1, 0]}
                    },
                    "port_scan_count": {
                        "$sum": {"$cond": [{"$in": ["$attack_type", ["Port Scan", "Reconnaissance"]]}, 1, 0]}
                    },
                    "normal_count": {
                        "$sum": {"$cond": [{"$eq": ["$attack_type", NORMAL_LABEL]}, 1, 0]}
                    }
                }
            },
            {"$sort": {"_id.y": 1, "_id.m": 1, "_id.d": 1, "_id.h": 1, "_id.minute": 1}}
        ]
        
        results = db.predictions.aggregate(pipeline)
        
        formatted_data = []
        for r in results:
            time_str = f"{r['_id']['h']:02d}:{r['_id']['minute']:02d}"
            formatted_data.append({
                "time": time_str,
                "DoS": r["dos_count"],
                "Port Scan": r["port_scan_count"],
                "Normal": r["normal_count"]
            })
            
        return formatted_data

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")