"""
ml_service.py v5.1 - BINARY OPTIMIZED (FINAL MERGE)
====================
56 features | Container-optimized DoS detection | Noise filtering | agent.py compatible
"""

import json, os, numpy as np
import joblib
from database import db as _db
from datetime import datetime, timedelta
from huggingface_hub import hf_hub_download

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────────────────────────────────────
REPO_ID = "AG1713/log-analytics-models"

# Global variables for Lazy Loading
binary_model = attack_et = attack_gb = attack_enc = None
proto_enc = service_enc = scaler = None
FEATURE_COLS = []
BINARY_THRESHOLD = 0.38
TYPE_THRESHOLD = 0.30
KNOWN_STATES = ["FIN","INT","CON","REQ","RST","ECO","PAR","URN","no"]

def _get_hf_path(filename):
    return hf_hub_download(repo_id=REPO_ID, filename=filename)

# ──────────────────────────────────────────────────────────────────────────────
# LAZY MODEL LOADER
# ──────────────────────────────────────────────────────────────────────────────
def load_models_once():
    global binary_model, attack_et, attack_gb, attack_enc
    global proto_enc, service_enc, scaler, FEATURE_COLS
    global BINARY_THRESHOLD, TYPE_THRESHOLD, KNOWN_STATES
    
    if binary_model is not None:
        return

    try:
        print("📦 Lazy loading massive ML models v5.1...", flush=True)
        
        # Load Model Artifacts (progress feedback)
        print("-> 1/7 Loading binary_model.pkl...", flush=True)
        binary_model = joblib.load(_get_hf_path("binary_model.pkl"))
        
        print("-> 2/7 Loading attack_clf_et.pkl...", flush=True)
        attack_et = joblib.load(_get_hf_path("attack_clf_et.pkl"))
        
        print("-> 3/7 Loading attack_clf_gb.pkl...", flush=True)
        attack_gb = joblib.load(_get_hf_path("attack_clf_gb.pkl"))
        
        print("-> 4/7 Loading encoders + scaler...", flush=True)
        attack_enc = joblib.load(_get_hf_path("attack_enc.pkl"))
        proto_enc = joblib.load(_get_hf_path("proto_enc.pkl"))
        service_enc = joblib.load(_get_hf_path("service_enc.pkl"))
        scaler = joblib.load(_get_hf_path("scaler.pkl"))

        # Load Metadata
        print("-> Loading feature meta...", flush=True)
        meta_path = _get_hf_path("feature_meta.json")
        with open(meta_path, 'r') as f:
            _meta = json.load(f)

        FEATURE_COLS = _meta["feature_cols"]
        BINARY_THRESHOLD = float(_meta.get("binary_threshold", 0.38))
        TYPE_THRESHOLD = float(_meta.get("attack_threshold", 0.30))
        KNOWN_STATES = _meta.get("known_states", KNOWN_STATES)

        print(f"✅ ML v5.1 loaded: {len(FEATURE_COLS)} features", flush=True)

    except Exception as e:
        print(f"[!] Model loading failed: {e}", flush=True)

# ──────────────────────────────────────────────────────────────────────────────
# MAPPINGS
# ──────────────────────────────────────────────────────────────────────────────
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
    "Normal": "low",
}

# ──────────────────────────────────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────────────────────────────────
def _f(log, key, default=0.0):
    try:
        val = log.get(key, default)
        return float(val if val is not None else default)
    except (TypeError, ValueError):
        return float(default)

def _safe_enc(encoder, value):
    try:
        v = str(value).strip().lower()
        if v in encoder.classes_:
            return float(encoder.transform([v])[0])
        return float(encoder.transform([encoder.classes_[0]])[0])
    except Exception:
        return 0.0

def _agent_or_formula(log, key, formula_value):
    v = log.get(key)
    if v is not None:
        try:
            fv = float(v)
            if not np.isnan(fv):
                return fv
        except (TypeError, ValueError):
            pass
    return formula_value

def _soft_vote(X, w_et=2, w_gb=1):
    p_et = attack_et.predict_proba(X)
    p_gb = attack_gb.predict_proba(X)
    return (p_et * w_et + p_gb * w_gb) / (w_et + w_gb)

# ──────────────────────────────────────────────────────────────────────────────
# FEATURE EXTRACTION v5.1 (56 features)
# ──────────────────────────────────────────────────────────────────────────────
def extract_features(log):
    if log.get("src_ip") in ("127.0.0.1", "0.0.0.0", None):
        return None

    # Raw values (early filtering)
    spkts = _f(log, "spkts")
    dpkts = _f(log, "dpkts")
    if spkts == 0 and dpkts == 0:
        return None

    dur = _f(log, "dur")
    sbytes = _f(log, "sbytes")
    dbytes = _f(log, "dbytes")
    rate = _f(log, "rate")
    sttl = _f(log, "sttl")
    dttl = _f(log, "dttl")
    synack = _f(log, "synack")
    ackdat = _f(log, "ackdat")

    proto_str = str(log.get("proto", "tcp")).strip().lower()
    service_str = str(log.get("service", "-")).strip().lower()
    state_raw = str(log.get("state", "CON")).strip().upper()

    proto_val = _safe_enc(proto_enc, proto_str)
    service_val = _safe_enc(service_enc, service_str)

    # Standard engineered features
    total_pkts = spkts + dpkts
    total_bytes = sbytes + dbytes
    byte_ratio = sbytes / (dbytes + 1)
    packet_ratio = spkts / (dpkts + 1)
    ttl_diff = sttl - dttl
    flow_packets = total_pkts
    flow_bytes = total_bytes
    bytes_per_pkt = total_bytes / (total_pkts + 1)
    pkt_rate = total_pkts / (dur + 1e-6)

    # Basic discriminators
    has_response = float(dpkts > 0)
    is_long_flow = float(dur > 10)
    small_payload = float(bytes_per_pkt < 100)
    asymmetric = float(sbytes / (dbytes + 1) > 10)

    # Interaction features
    state_is_int = state_raw == "INT"
    state_is_fin = state_raw == "FIN"

    int_no_response = float(state_is_int and dpkts == 0 and spkts > 10)
    int_small_bytes = float(state_is_int and sbytes < 500)
    int_high_spkts = float(state_is_int and spkts > 20)
    fin_small_payload = float(state_is_fin and bytes_per_pkt < 150)
    
    # ── TUNED DOS SIGNATURE FOR CONTAINER NETWORKS ──
    # Triggers if high volume OR one-sided teardown (typical for hping3 samples)
    dos_signature = float(
        (spkts > 50 and dpkts < spkts * 0.1) or 
        (spkts >= 2 and dpkts == 0 and state_raw in ["FIN", "INT", "RST"])
    )
    
    backdoor_signature = float(state_is_int and dpkts > 0 and dpkts < spkts and dur > 0)

    # Agent-computed v3.1 (use agent values OR compute)
    syn_ratio = _agent_or_formula(log, "syn_ratio", float(np.clip(spkts / (total_pkts + 1), 0, 1)))
    ack_ratio = _agent_or_formula(log, "ack_ratio", float(np.clip(dpkts / (total_pkts + 1), 0, 1)))
    rst_ratio = _agent_or_formula(log, "rst_ratio", float(state_raw == "RST"))
    iat_ratio = _agent_or_formula(log, "iat_ratio", float(np.clip(np.log1p(rate) / 15.0, 0, 3)))
    unique_ports_per_ip = _agent_or_formula(log, "unique_ports_per_ip", float(np.clip(np.log1p(spkts) * float(service_str == "-"), 0, 10)))
    connections_per_ip_window = _agent_or_formula(log, "connections_per_ip_window", float(np.clip(np.log1p(sbytes), 0, 15)))
    failed_connection_ratio = _agent_or_formula(log, "failed_connection_ratio", float(np.clip(1.0 - (dpkts / (spkts + 1)), 0, 1)))

    # v4.0 kept
    log_byte_asymmetry = float(np.clip(np.log1p(sbytes) - np.log1p(dbytes), -5, 10))

    # v5.0 Response features
    dttl_gt0 = float(dttl > 0)
    ackdat_gt0 = float(ackdat > 0)
    dbytes_gt0 = float(dbytes > 0)
    real_connection = float(dttl > 0 and ackdat > 0 and dbytes > 0)
    tcp_established = float(proto_str == "tcp" and dttl > 0 and dbytes > 0)
    log_dbytes = float(np.clip(np.log1p(dbytes), 0, 15))
    service_known = float(service_str != "-")
    sttl_normal = float(sttl in (64, 128, 255, 32))

    # NEW v5.1 Binary-focused
    normal_like = float(dttl_gt0 > 0.5 and service_known > 0.2 and log_dbytes > 3)
    attack_like = float((log_byte_asymmetry > 3) or (pkt_rate > 1000) or (dos_signature > 0))

    # State OHE (9 states)
    state_ohe = [float(state_raw == s if s != "no" else state_raw.lower() == "no") for s in KNOWN_STATES]

    # ── EXACT 56-FEATURE ORDER ──
    raw = np.array([[
        # Core flow (12)
        dur, proto_val, service_val, spkts, dpkts, sbytes, dbytes, rate, sttl, dttl, synack, ackdat,
        
        # Standard engineered (7)
        byte_ratio, packet_ratio, ttl_diff, flow_packets, flow_bytes, bytes_per_pkt, pkt_rate,
        
        # Basic discriminators (4)
        has_response, is_long_flow, small_payload, asymmetric,
        
        # Interaction features (6)
        int_no_response, int_small_bytes, int_high_spkts, fin_small_payload, dos_signature, backdoor_signature,
        
        # Agent v3.1 (7)
        syn_ratio, ack_ratio, rst_ratio, iat_ratio, unique_ports_per_ip, connections_per_ip_window, failed_connection_ratio,
        
        # v4.0 kept (1)
        log_byte_asymmetry,
        
        # v5.0 Response (8)
        dttl_gt0, ackdat_gt0, dbytes_gt0, real_connection, tcp_established, log_dbytes, service_known, sttl_normal,
        
        # NEW v5.1 Binary-focused (2)
        normal_like, attack_like,
        
        # State one-hot (9)
        *state_ohe
    ]], dtype=np.float32)

    if raw.shape[1] != len(FEATURE_COLS):
        print(f"[!] Feature mismatch: got {raw.shape[1]}, expected {len(FEATURE_COLS)}")
        return None

    return scaler.transform(raw)

# ──────────────────────────────────────────────────────────────────────────────
# MAIN PREDICTION PIPELINE
# ──────────────────────────────────────────────────────────────────────────────
def predict(log: dict) -> "dict | None":
    load_models_once()

    if binary_model is None:
        return {"prediction": "Unknown", "attack_type": "Model Error", "confidence": 0.0, "anomaly": False, "severity": "low"}

    # 1. NOISE FILTER GATE (both significant flag AND packet volume)
    is_significant = log.get("is_significant", True)
    spkts = _f(log, "spkts")
    dpkts = _f(log, "dpkts")
    
    # Auto-label low-volume heartbeats as Normal
    if not is_significant or (spkts + dpkts < 5):
        return {
            "prediction": "Normal", "attack_type": "None", "confidence": 1.0,
            "type_confidence": 1.0, "anomaly": False, "severity": "low",
        }

    features = extract_features(log)
    if features is None:
        return None

    # Binary prediction
    probs = binary_model.predict_proba(features)[0]
    classes = list(binary_model.classes_)
    attack_idx = classes.index(1) if 1 in classes else 1
    attack_prob = float(probs[attack_idx])
    benign_prob = 1.0 - attack_prob

    # 2. INTERNAL CONTAINER THRESHOLD FIX (0.45 for Docker traffic)
    src_ip = str(log.get("src_ip", ""))
    effective_threshold = 0.45 if src_ip.startswith("172.17.") else BINARY_THRESHOLD

    if attack_prob >= effective_threshold:
        # Resolve attack type with soft voting
        type_probs = _soft_vote(features)
        top_idx = int(np.argmax(type_probs[0]))
        attack_type = attack_enc.classes_[top_idx]
        type_conf = float(type_probs[0][top_idx])

        # ── VETERAN SAFETY CHECKS ──
        # Resolve "Suspicious Unknown" into "DoS" if it fits the signature
        if (attack_type == "suspicious_unknown" or type_conf < 0.35) and _f(log, "dpkts") == 0:
            attack_type = "DoS"
        
        # Final safety: if still very low type confidence, call it Normal
        if type_conf < 0.20 and attack_type == "suspicious_unknown":
            return {
                "prediction": "Normal", "attack_type": "None", 
                "confidence": round(benign_prob, 4), 
                "type_confidence": round(type_conf, 4),
                "anomaly": False, "severity": "low"
            }

        return {
            "prediction": "Attack",
            "attack_type": attack_type,
            "confidence": round(attack_prob, 4),
            "type_confidence": round(type_conf, 4),
            "anomaly": True,
            "severity": SEVERITY_MAP.get(attack_type, "high"),
        }
    
    return {
        "prediction": "Normal",
        "attack_type": "None",
        "confidence": round(benign_prob, 4),
        "type_confidence": 1.0,
        "anomaly": False,
        "severity": "low",
    }

# ──────────────────────────────────────────────────────────────────────────────
# SHARED API ENDPOINTS
# ──────────────────────────────────────────────────────────────────────────────
def predict_log(log: dict) -> None:
    """Run inference on MongoDB log document (called by main.py worker)."""
    result = predict(log)
    if result is None:
        log["prediction"] = "Skipped"
        log["attack_type"] = "None"
        log["confidence"] = 0.0
        log["type_confidence"] = 0.0
        log["anomaly"] = False
        log["severity"] = "low"
        return

    for k, v in result.items():
        log[k] = v

def generate_attack_summary():
    """Return attack counts + avg confidence from last 5 minutes."""
    try:
        network_logs = _db.network_logs
        last_5_min = datetime.utcnow() - timedelta(minutes=5)
        pipeline = [
            {"$match": {"prediction": "Attack", "timestamp": {"$gte": last_5_min.isoformat()}}},
            {"$group": {"_id": "$attack_type", "count": {"$sum": 1}, "avg_confidence": {"$avg": "$confidence"}}},
            {"$sort": {"count": -1}}, {"$limit": 10}
        ]
        results = list(network_logs.aggregate(pipeline))
        return [{"attack_type": r["_id"], "count": int(r["count"]), "avg_confidence": round(float(r.get("avg_confidence", 0)), 4)} for r in results]
    except Exception as e:
        return [{"error": str(e), "count": 0, "avg_confidence": 0.0}]

def predict_http_endpoint(log_data: dict):
    """Direct HTTP prediction (for agent.py direct calls)."""
    result = predict(log_data)
    return {"status": "success" if result else "skipped", "data": result or {"prediction": "Skipped", "confidence": 0.0}}

# ──────────────────────────────────────────────────────────────────────────────
# TEST ENTRYPOINT (runs only when: python ml_service.py)
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    sample_log = {
        "src_ip": "192.168.1.100", "dst_ip": "8.8.8.8",
        "src_port": 54321, "dst_port": 53,
        "proto": "udp", "state": "CON", "service": "dns",
        "dur": 0.15, "spkts": 5, "dpkts": 2,
        "sbytes": 180, "dbytes": 120,
        "sttl": 64, "dttl": 56, "synack": 0.02, "ackdat": 0.01,
        "is_significant": True
    }

    result = predict(sample_log)
    print("🧪 Test prediction:", json.dumps(result, indent=2))

    print("\n📊 Last 5min attack summary:")
    print(json.dumps(generate_attack_summary(), indent=2))