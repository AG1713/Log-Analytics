import os
import joblib
import pandas as pd
from collections import Counter

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.getenv("ML_DATA_PATH")

if not DATA_PATH:
    PROJECT_ROOT = os.path.dirname(BASE_DIR)
    DATA_PATH = os.path.join(PROJECT_ROOT, "ml_training", "unsw", "UNSW_NB15_testing-set.csv")

MODEL_PATH = os.path.join(BASE_DIR, "trained_model", "unsw_attack_classifier.pkl")
ENCODER_PATH = os.path.join(BASE_DIR, "trained_model", "unsw_label_encoder.pkl")

model = joblib.load(MODEL_PATH)
label_encoder = joblib.load(ENCODER_PATH)

SEVERITY_MAP = {
    "Normal": "normal",
    "Worms": "critical",
    "Backdoor": "critical",
    "Backdoors": "critical",
    "Shellcode": "critical",
    "Exploits": "high",
    "DoS": "high",
    "Generic": "medium",
    "Fuzzers": "medium",
    "Reconnaissance": "low",
    "Analysis": "medium",
}


def normalize_attack_name(name):
    if pd.isna(name):
        return "Unknown"
    name = str(name).strip()
    if not name:
        return "Unknown"
    if name.lower() == "backdoors":
        return "Backdoor"
    return name


def generate_attack_summary():
    print("Reading file from:", DATA_PATH)

    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(f"CSV file not found at: {DATA_PATH}")

    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Model file not found at: {MODEL_PATH}")

    if not os.path.exists(ENCODER_PATH):
        raise FileNotFoundError(f"Label encoder file not found at: {ENCODER_PATH}")

    df = pd.read_csv(DATA_PATH)

    required_cols = ["proto", "service", "state"]
    missing_required = [col for col in required_cols if col not in df.columns]
    if missing_required:
        raise KeyError(f"Missing required columns: {missing_required}")

    proto_raw = df["proto"].fillna("unknown").astype(str).copy()
    service_raw = df["service"].fillna("-").astype(str).copy()
    state_raw = df["state"].fillna("UNK").astype(str).copy()

    df_model = df.drop(columns=["id", "label", "attack_cat"], errors="ignore").copy()

    categorical_cols = ["proto", "service", "state"]
    for col in categorical_cols:
        df_model[col] = df_model[col].fillna("unknown").astype("category").cat.codes

    try:
        predictions = model.predict(df_model)
    except Exception as e:
        raise RuntimeError(f"Model prediction failed: {e}")

    try:
        decoded = label_encoder.inverse_transform(predictions)
    except Exception as e:
        raise RuntimeError(f"Label decoding failed: {e}")

    decoded = [normalize_attack_name(x) for x in decoded]
    df["predicted_cat"] = decoded

    attack_counts = Counter(decoded)
    total = len(decoded)
    total_normal = attack_counts.get("Normal", 0)
    total_attacks = total - total_normal

    severity_counts = Counter()
    for cat, count in attack_counts.items():
        sev = SEVERITY_MAP.get(cat, "low")
        severity_counts[sev] += count

    attack_mask = df["predicted_cat"] != "Normal"

    proto_counts = Counter(proto_raw[attack_mask].str.lower())
    service_counts = Counter(
        s for s in service_raw[attack_mask].str.lower()
        if s.strip() and s.strip() != "-"
    )
    state_counts = Counter(state_raw[attack_mask].str.upper())

    return {
        "data_path": DATA_PATH,
        "total_records": total,
        "total_attacks": total_attacks,
        "total_normal": total_normal,
        "attack_distribution": dict(attack_counts),
        "severity_distribution": dict(severity_counts),
        "protocol_distribution": dict(proto_counts.most_common(6)),
        "service_distribution": dict(service_counts.most_common(6)),
        "state_distribution": dict(state_counts.most_common(10)),
    }


if __name__ == "__main__":
    summary = generate_attack_summary()
    print(summary)