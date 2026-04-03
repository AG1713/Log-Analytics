import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

# ============================
# 📥 LOAD DATASET
# ============================

DATA_PATH = "UNSW_NB15_training-set.csv"   # 🔥 CHANGE if needed
df = pd.read_csv(DATA_PATH)

print(f"ℹ️ Dataset loaded → {len(df)} rows")

# ============================
# 🔧 FIX LABEL COLUMN
# ============================

if "attack" in df.columns:
    df["label_final"] = df["attack"]

elif "attack_cat" in df.columns:
    df["label_final"] = df["attack_cat"]

else:
    raise Exception(f"❌ No attack label column found. Columns: {df.columns}")

# Remove null labels
df = df[df["label_final"].notna()]

# ============================
# 🧹 CLEAN + MERGE CLASSES
# ============================

RARE_CLASSES = ["Analysis", "Backdoor", "Shellcode", "Worms"]

df["label_final"] = df["label_final"].replace(RARE_CLASSES, "Rare_Attack")

# ============================
# 🔧 FEATURE ENGINEERING
# ============================

df["byte_ratio"]   = df["sbytes"] / (df["dbytes"] + 1)
df["packet_ratio"] = df["spkts"] / (df["dpkts"] + 1)
df["ttl_diff"]     = df["sttl"] - df["dttl"]

FEATURES = [
    "dur", "proto", "service", "spkts", "dpkts",
    "sbytes", "dbytes", "rate", "sttl", "dttl",
    "byte_ratio", "packet_ratio", "ttl_diff"
]

X = df[FEATURES].copy()
y = df["label_final"]

# ============================
# 🔧 ENCODING
# ============================

proto_enc = LabelEncoder()
service_enc = LabelEncoder()
attack_enc = LabelEncoder()

X["proto"] = proto_enc.fit_transform(X["proto"].astype(str))
X["service"] = service_enc.fit_transform(X["service"].astype(str))

y_encoded = attack_enc.fit_transform(y)

# ============================
# ⚖️ TRAIN / TEST SPLIT
# ============================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y_encoded,
    test_size=0.2,
    stratify=y_encoded,
    random_state=42
)

# ============================
# 🔧 SCALING
# ============================

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled  = scaler.transform(X_test)

# ============================
# 🧠 MODEL (PRECISION-FIRST)
# ============================

# 🔥 Penalize DoS to reduce false positives
class_weights = {}

if "DoS" in attack_enc.classes_:
    dos_index = attack_enc.transform(["DoS"])[0]
    class_weights[dos_index] = 0.5   # reduce DoS aggressiveness

model = RandomForestClassifier(
    n_estimators=300,
    max_depth=20,
    min_samples_leaf=5,
    class_weight=class_weights if class_weights else None,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train_scaled, y_train)

# ============================
# 📊 EVALUATION
# ============================

y_pred = model.predict(X_test_scaled)

print("\n📊 Classification Report:\n")
print(classification_report(
    y_test,
    y_pred,
    target_names=attack_enc.classes_
))

# ============================
# 💾 SAVE MODELS
# ============================

joblib.dump(model, "models/binary_model.pkl")
joblib.dump(proto_enc, "models/proto_enc.pkl")
joblib.dump(service_enc, "models/service_enc.pkl")
joblib.dump(attack_enc, "models/attack_enc.pkl")
joblib.dump(scaler, "models/scaler.pkl")

print("\n✅ Model saved successfully!")