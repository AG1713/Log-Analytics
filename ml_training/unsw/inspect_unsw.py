import pandas as pd

# Load datasets
train_df = pd.read_csv("UNSW_NB15_training-set.csv")
test_df = pd.read_csv("UNSW_NB15_testing-set.csv")

print("========== TRAIN DATA ==========")
print("Shape:", train_df.shape)
print("\nColumns:\n", train_df.columns.tolist())

print("\nAttack Categories (Train):")
print(train_df['attack_cat'].value_counts())

print("\n========== TEST DATA ==========")
print("Shape:", test_df.shape)

print("\nAttack Categories (Test):")
print(test_df['attack_cat'].value_counts())