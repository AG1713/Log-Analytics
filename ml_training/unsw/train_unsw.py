import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt

from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

print("Loading dataset...")

# -----------------------
# 1. Load Data
# -----------------------
train_df = pd.read_csv("UNSW_NB15_training-set.csv")
test_df = pd.read_csv("UNSW_NB15_testing-set.csv")

# Combine train + test
df = pd.concat([train_df, test_df], axis=0)

print("Total dataset shape:", df.shape)

# -----------------------
# 2. Drop Unnecessary Columns
# -----------------------
df = df.drop(columns=["id", "label"])

# -----------------------
# 3. Encode Categorical Features
# -----------------------
categorical_cols = ["proto", "service", "state"]

for col in categorical_cols:
    encoder = LabelEncoder()
    df[col] = encoder.fit_transform(df[col])

# -----------------------
# 4. Encode Target (attack type)
# -----------------------
target_encoder = LabelEncoder()
df["attack_cat"] = target_encoder.fit_transform(df["attack_cat"])

# -----------------------
# 5. Split Features and Target
# -----------------------
X = df.drop(columns=["attack_cat"])
y = df["attack_cat"]

print("Feature shape:", X.shape)
print("Number of classes:", len(np.unique(y)))

# -----------------------
# 6. Train-Test Split
# -----------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

print("Training XGBoost model...")

# -----------------------
# 7. Train XGBoost
# -----------------------
model = XGBClassifier(
    n_estimators=300,
    max_depth=8,
    learning_rate=0.1,
    objective="multi:softmax",
    num_class=len(np.unique(y)),
    eval_metric="mlogloss",
    random_state=42
)

model.fit(X_train, y_train)

print("Model trained.")

# -----------------------
# 8. Evaluate Model
# -----------------------
y_pred = model.predict(X_test)

print("\nClassification Report:\n")
print(classification_report(y_test, y_pred))

# -----------------------
# 9. Feature Importance
# -----------------------
print("\nTop 15 Important Features:\n")

importances = model.feature_importances_
feature_names = X.columns

indices = np.argsort(importances)[::-1]

for i in range(15):
    print(f"{i+1}. {feature_names[indices[i]]} - {importances[indices[i]]:.4f}")

# Optional plot
plt.figure(figsize=(10,6))
plt.title("Top 15 Feature Importances")
plt.barh(range(15), importances[indices[:15]][::-1])
plt.yticks(range(15), feature_names[indices[:15]][::-1])
plt.xlabel("Importance")
plt.tight_layout()
plt.show()

# -----------------------
# 10. Save Model & Encoder
# -----------------------
joblib.dump(model, "unsw_attack_classifier.pkl")
joblib.dump(target_encoder, "unsw_label_encoder.pkl")

print("\nUNSW XGBoost Attack Classifier Saved Successfully")