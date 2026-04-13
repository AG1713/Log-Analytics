"""
diagnose_data.py
================
Run this FIRST before train_model.py to see what your specific
UNSW CSV files actually contain. The training-set.csv is a
preprocessed subset with distributions that differ from the raw
UNSW-NB15_1..4.csv files — we need to discover the real values.

Usage: python diagnose_data.py
Output: prints a feature_report.txt you paste back to get a targeted fix.
"""

import os
import json
import pandas as pd
import numpy as np


OUTPUT_FILE = "feature_report.txt"

CSV_CANDIDATES = [
    "UNSW_NB15_training-set.csv",
    "UNSW_NB15_testing-set.csv",
    "UNSW-NB15_1.csv", "UNSW-NB15_2.csv",
    "UNSW-NB15_3.csv", "UNSW-NB15_4.csv",
]

CLASSES_OF_INTEREST = [
    "DoS", "Backdoor", "Analysis", "Normal", "Reconnaissance", "Generic"
]


def load_data():
    frames = []
    for p in CSV_CANDIDATES:
        if os.path.exists(p):
            print(f"  Loading {p} ...")
            frames.append(pd.read_csv(p, low_memory=False))

    if not frames:
        raise FileNotFoundError("No UNSW CSV found in current directory.")

    df = pd.concat(frames, ignore_index=True)
    df.columns = [c.strip().lower() for c in df.columns]

    if "attack_cat" not in df.columns:
        raise KeyError("Required column 'attack_cat' not found in the CSV files.")

    df["attack_cat"] = (
        df["attack_cat"]
        .fillna("Normal")
        .astype(str)
        .str.strip()
        .str.title()
        .replace({
            "": "Normal",
            "Nan": "Normal",
            "Dos": "DoS",
            "Recon": "Reconnaissance",
            "Backdoors": "Backdoor"
        })
    )

    for c in [
        "dur", "spkts", "dpkts", "sbytes", "dbytes", "rate",
        "sttl", "dttl", "synack", "ackdat", "label"
    ]:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0)

    df["proto"] = (
        df.get("proto", pd.Series(["other"] * len(df)))
        .fillna("other")
        .astype(str)
        .str.strip()
        .str.lower()
    )

    df["service"] = (
        df.get("service", pd.Series(["-"] * len(df)))
        .fillna("-")
        .astype(str)
        .str.strip()
        .str.lower()
    )

    df["state"] = (
        df.get("state", pd.Series(["CON"] * len(df)))
        .fillna("CON")
        .astype(str)
        .str.strip()
        .str.upper()
    )

    return df


def report_feature(df, feat_name, series_fn, lines):
    lines.append(f"\n--- {feat_name} ---")
    results = {}

    for cls in CLASSES_OF_INTEREST:
        sub = df[df["attack_cat"] == cls]
        if len(sub) == 0:
            continue

        vals = series_fn(sub)
        vals = pd.to_numeric(vals, errors="coerce").fillna(0)

        results[cls] = {
            "mean": round(float(vals.mean()), 4),
            "median": round(float(vals.median()), 4),
            "std": round(float(vals.std()), 4),
            "p25": round(float(vals.quantile(0.25)), 4),
            "p75": round(float(vals.quantile(0.75)), 4),
        }

        lines.append(
            f"  {cls:<16}: mean={results[cls]['mean']:>8.4f}  "
            f"median={results[cls]['median']:>8.4f}  "
            f"std={results[cls]['std']:>8.4f}  "
            f"p25={results[cls]['p25']:>8.4f}  "
            f"p75={results[cls]['p75']:>8.4f}"
        )

    return results


def report_categorical(df, feat_name, col, lines):
    lines.append(f"\n--- {feat_name} (top values per class) ---")
    results = {}

    for cls in CLASSES_OF_INTEREST:
        sub = df[df["attack_cat"] == cls]
        if len(sub) == 0:
            continue

        vc = sub[col].value_counts(normalize=True).head(5)
        results[cls] = dict(vc)

        vals_str = "  ".join([f"{k}:{v:.3f}" for k, v in vc.items()])
        lines.append(f"  {cls:<16}: {vals_str}")

    return results


def compute_separability(all_results):
    """
    For each feature, compute how well it separates the problem classes.
    Score = std of class means / mean of class stds (higher = more separable)
    """
    scores = {}

    for feat, class_data in all_results.items():
        if not class_data:
            continue

        first_val = list(class_data.values())[0]
        if not isinstance(first_val, dict):
            continue

        problem_classes = ["DoS", "Backdoor", "Analysis"]
        means = [class_data[c]["mean"] for c in problem_classes if c in class_data]
        stds = [class_data[c]["std"] for c in problem_classes if c in class_data]

        if len(means) < 2:
            continue

        between_class_spread = np.std(means)
        within_class_spread = np.mean(stds) + 1e-9
        scores[feat] = round(between_class_spread / within_class_spread, 4)

    return sorted(scores.items(), key=lambda x: -x[1])


def main():
    print("=" * 65)
    print("UNSW-NB15 DATA DISTRIBUTION DIAGNOSIS")
    print("=" * 65)

    print("\nLoading data ...")
    df = load_data()
    print(f"Total rows: {len(df):,}\n")

    lines = []
    lines.append("=" * 65)
    lines.append("UNSW-NB15 ACTUAL FEATURE DISTRIBUTIONS")
    lines.append("=" * 65)
    lines.append(f"Total rows: {len(df):,}")

    lines.append("\n\n=== CLASS COUNTS ===")
    vc = df["attack_cat"].value_counts()
    for cls, cnt in vc.items():
        lines.append(f"  {cls:<20}: {cnt:>7,}")

    all_results = {}

    lines.append("\n\n=== CONTINUOUS FEATURES ===")

    numeric_features = {
        "sbytes": lambda s: pd.to_numeric(s["sbytes"], errors="coerce").fillna(0),
        "dbytes": lambda s: pd.to_numeric(s["dbytes"], errors="coerce").fillna(0),
        "spkts": lambda s: pd.to_numeric(s["spkts"], errors="coerce").fillna(0),
        "dpkts": lambda s: pd.to_numeric(s["dpkts"], errors="coerce").fillna(0),
        "dur": lambda s: pd.to_numeric(s["dur"], errors="coerce").fillna(0),
        "rate": lambda s: pd.to_numeric(s["rate"], errors="coerce").fillna(0),
        "sttl": lambda s: pd.to_numeric(s["sttl"], errors="coerce").fillna(0),
        "dttl": lambda s: pd.to_numeric(s["dttl"], errors="coerce").fillna(0),
        "synack": lambda s: pd.to_numeric(s["synack"], errors="coerce").fillna(0),
        "ackdat": lambda s: pd.to_numeric(s["ackdat"], errors="coerce").fillna(0),

        "log_sbytes": lambda s: np.log1p(pd.to_numeric(s["sbytes"], errors="coerce").fillna(0)),
        "log_dbytes": lambda s: np.log1p(pd.to_numeric(s["dbytes"], errors="coerce").fillna(0)),
        "log_spkts": lambda s: np.log1p(pd.to_numeric(s["spkts"], errors="coerce").fillna(0)),
        "log_dpkts": lambda s: np.log1p(pd.to_numeric(s["dpkts"], errors="coerce").fillna(0)),
        "log_dur": lambda s: np.log1p(pd.to_numeric(s["dur"], errors="coerce").fillna(0)),
        "log_rate": lambda s: np.log1p(pd.to_numeric(s["rate"], errors="coerce").fillna(0)),

        "byte_asymmetry": lambda s:
            np.log1p(pd.to_numeric(s["sbytes"], errors="coerce").fillna(0))
            - np.log1p(pd.to_numeric(s["dbytes"], errors="coerce").fillna(0)),

        "pkt_asymmetry": lambda s:
            pd.to_numeric(s["spkts"], errors="coerce").fillna(0)
            - pd.to_numeric(s["dpkts"], errors="coerce").fillna(0),

        "dttl_gt0": lambda s: (pd.to_numeric(s["dttl"], errors="coerce").fillna(0) > 0).astype(float),
        "ackdat_gt0": lambda s: (pd.to_numeric(s["ackdat"], errors="coerce").fillna(0) > 0).astype(float),
        "synack_gt0": lambda s: (pd.to_numeric(s["synack"], errors="coerce").fillna(0) > 0).astype(float),
        "dbytes_gt0": lambda s: (pd.to_numeric(s["dbytes"], errors="coerce").fillna(0) > 0).astype(float),
        "service_known": lambda s: (s["service"].fillna("-").str.strip() != "-").astype(float),
        "proto_tcp": lambda s: (s["proto"].fillna("").str.strip().str.lower() == "tcp").astype(float),
        "proto_udp": lambda s: (s["proto"].fillna("").str.strip().str.lower() == "udp").astype(float),
        "sttl_is_64": lambda s: (pd.to_numeric(s["sttl"], errors="coerce").fillna(0) == 64).astype(float),
        "sttl_is_128": lambda s: (pd.to_numeric(s["sttl"], errors="coerce").fillna(0) == 128).astype(float),
        "dttl_is_64": lambda s: (pd.to_numeric(s["dttl"], errors="coerce").fillna(0) == 64).astype(float),
        "dttl_is_128": lambda s: (pd.to_numeric(s["dttl"], errors="coerce").fillna(0) == 128).astype(float),

        "real_connection": lambda s: (
            (pd.to_numeric(s["dttl"], errors="coerce").fillna(0) > 0) &
            (pd.to_numeric(s["ackdat"], errors="coerce").fillna(0) > 0) &
            (pd.to_numeric(s["dbytes"], errors="coerce").fillna(0) > 0)
        ).astype(float),

        "tcp_established": lambda s: (
            (s["proto"].fillna("").str.lower() == "tcp") &
            (pd.to_numeric(s["dttl"], errors="coerce").fillna(0) > 0) &
            (pd.to_numeric(s["dbytes"], errors="coerce").fillna(0) > 0)
        ).astype(float),

        "state_FIN": lambda s: (s["state"].fillna("").str.upper() == "FIN").astype(float),
        "state_CON": lambda s: (s["state"].fillna("").str.upper() == "CON").astype(float),
        "state_INT": lambda s: (s["state"].fillna("").str.upper() == "INT").astype(float),
        "state_RST": lambda s: (s["state"].fillna("").str.upper() == "RST").astype(float),
        "state_REQ": lambda s: (s["state"].fillna("").str.upper() == "REQ").astype(float),
    }

    for feat_name, fn in numeric_features.items():
        try:
            result = report_feature(df, feat_name, fn, lines)
            all_results[feat_name] = result
        except KeyError:
            lines.append(f"\n--- {feat_name} ---")
            lines.append("  Skipped: required source column missing.")

    lines.append("\n\n=== CATEGORICAL DISTRIBUTIONS ===")
    for col in ["state", "proto", "service"]:
        if col in df.columns:
            report_categorical(df, col, col, lines)

    lines.append("\n\n=== FEATURE SEPARABILITY RANKING (DoS vs Backdoor vs Analysis) ===")
    lines.append("Higher score = better at separating the 3 problem classes")
    scores = compute_separability(all_results)

    for feat, score in scores[:25]:
        bar = "█" * min(int(score * 10), 40)
        lines.append(f"  {feat:<30} score={score:>7.4f}  {bar}")

    lines.append("\n\n=== KEY QUESTION: What differs between DoS, Backdoor, Analysis? ===")
    for feat in [
        "dttl_gt0", "ackdat_gt0", "dbytes_gt0", "real_connection",
        "tcp_established", "service_known", "state_FIN", "state_CON",
        "sttl_is_64", "dttl_is_64", "byte_asymmetry", "log_dur"
    ]:
        if feat not in all_results:
            continue

        r = all_results[feat]
        dos_val = r.get("DoS", {}).get("mean", "N/A")
        back_val = r.get("Backdoor", {}).get("mean", "N/A")
        anal_val = r.get("Analysis", {}).get("mean", "N/A")
        norm_val = r.get("Normal", {}).get("mean", "N/A")

        lines.append(
            f"  {feat:<25}: DoS={dos_val:>7}  Backdoor={back_val:>7}  "
            f"Analysis={anal_val:>7}  Normal={norm_val:>7}"
        )

    report_text = "\n".join(lines)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(report_text)

    print(report_text)
    print(f"\n✅ Report saved to {OUTPUT_FILE}")
    print("   Paste the contents of feature_report.txt to get a targeted v5.0 fix.")


if __name__ == "__main__":
    main()