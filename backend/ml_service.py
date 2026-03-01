import joblib
import pandas as pd
import os
from collections import Counter

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

model = joblib.load(os.path.join(BASE_DIR, "trained_model", "unsw_attack_classifier.pkl"))
label_encoder = joblib.load(os.path.join(BASE_DIR, "trained_model", "unsw_label_encoder.pkl"))

def generate_attack_summary():

    df = pd.read_csv(os.path.join(BASE_DIR, "UNSW_NB15_testing-set.csv"))

    df = df.drop(columns=["id", "label"])

    categorical_cols = ["proto", "service", "state"]

    for col in categorical_cols:
        df[col] = df[col].astype("category").cat.codes

    X = df.drop(columns=["attack_cat"])

    predictions = model.predict(X)

    decoded = label_encoder.inverse_transform(predictions)

    counts = Counter(decoded)

    total = sum(counts.values())

    return {
        "total_attacks": total,
        "distribution": counts
    }