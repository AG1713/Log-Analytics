import pandas as pd
import joblib
import json
import os
from collections import Counter

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

print("Loading model...")

model = joblib.load(os.path.join(BASE_DIR, "unsw", "unsw_attack_classifier.pkl"))
label_encoder = joblib.load(os.path.join(BASE_DIR, "unsw", "unsw_label_encoder.pkl"))

print("Loading dataset...")

df = pd.read_csv(os.path.join(BASE_DIR, "unsw", "UNSW_NB15_testing-set.csv"))

df = df.drop(columns=["id", "label"])

categorical_cols = ["proto", "service", "state"]

for col in categorical_cols:
    df[col] = df[col].astype("category").cat.codes

X = df.drop(columns=["attack_cat"])

print("Running predictions...")

predictions = model.predict(X)

decoded = label_encoder.inverse_transform(predictions)

counts = Counter(decoded)

total = sum(counts.values())

summary = {
    "total_attacks": total,
    "distribution": dict(counts)
}

print("Saving JSON...")

with open(os.path.join(BASE_DIR, "attack_summary.json"), "w") as f:
    json.dump(summary, f, indent=4)

print("Done. JSON file created.")