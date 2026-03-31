import joblib
import pandas as pd
import os
from collections import Counter

BASE_DIR = os.path.dirname(os.path.abspath(__file__)) # This is /app inside Docker
DATA_PATH = os.getenv("ML_DATA_PATH")
if not DATA_PATH:
    # This part runs if you are NOT in Docker (your original logic)
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    PROJECT_ROOT = os.path.dirname(BASE_DIR)
    DATA_PATH = os.path.join(PROJECT_ROOT, "ml_training", "unsw", "UNSW_NB15_testing-set.csv")

model = joblib.load(os.path.join(BASE_DIR, "trained_model", "unsw_attack_classifier.pkl"))
label_encoder = joblib.load(os.path.join(BASE_DIR, "trained_model", "unsw_label_encoder.pkl"))

# Map attack categories to severity levels
SEVERITY_MAP = {
    "Normal":         "normal",
    "Worms":          "critical",
    "Backdoors":      "critical",
    "Shellcode":      "critical",
    "Exploits":       "high",
    "DoS":            "high",
    "Generic":        "medium",
    "Fuzzers":        "medium",
    "Reconnaissance": "low",
}

def generate_attack_summary():
    print("Reading file from:", DATA_PATH)

    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(f"CSV file not found at: {DATA_PATH}")

    df = pd.read_csv(DATA_PATH)

    categorical_cols = ["proto", "service", "state"]

    # Save original values before encoding for distribution stats
    proto_raw   = df["proto"].copy()
    service_raw = df["service"].copy()
    state_raw   = df["state"].copy()

    df_model = df.drop(columns=["id", "label", "attack_cat"])
    for col in categorical_cols:
        df_model[col] = df_model[col].astype("category").cat.codes

    X = df_model
    predictions = model.predict(X)
    decoded = label_encoder.inverse_transform(predictions)

    df["predicted_cat"] = decoded

    # --- Attack distribution ---
    attack_counts = Counter(decoded)
    total = sum(attack_counts.values())
    attack_only = {k: v for k, v in attack_counts.items() if k != "Normal"}

    # --- Severity distribution ---
    severity_counts = Counter()
    for cat, count in attack_counts.items():
        sev = SEVERITY_MAP.get(cat, "low")
        severity_counts[sev] += count

    # --- Protocol distribution (attacks only) ---
    attack_mask = df["predicted_cat"] != "Normal"
    proto_counts = Counter(proto_raw[attack_mask].str.lower())

    # --- Service distribution (attacks only, exclude "-") ---
    service_counts = Counter(
        s for s in service_raw[attack_mask].str.lower() if s != "-"
    )

    # --- State distribution (attacks only) ---
    state_counts = Counter(state_raw[attack_mask].str.upper())

    return {
        "total_records":        total,
        "total_attacks":        total - attack_counts.get("Normal", 0),
        "total_normal":         attack_counts.get("Normal", 0),
        "attack_distribution":  dict(attack_counts),
        "severity_distribution": dict(severity_counts),
        "protocol_distribution": dict(proto_counts.most_common(6)),
        "service_distribution":  dict(service_counts.most_common(6)),
        "state_distribution":    dict(state_counts)
    }
