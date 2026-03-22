import pandas as pd
from pymongo import MongoClient

def export_all_siem_data():
    client = MongoClient("mongodb://localhost:27017/")
    db = client["siem_db"]
    
    # List of all collections your agent is filling
    collections_to_export = ["network_logs", "raw_logs", "fim_events"]

    for col_name in collections_to_export:
        print(f"[*] Processing {col_name}...")
        collection = db[col_name]
        data = list(collection.find())

        if not data:
            print(f"  [!] No data found in {col_name}, skipping.")
            continue

        # Convert to DataFrame
        df = pd.DataFrame(data)

        # Remove the MongoDB internal ID
        if '_id' in df.columns:
            df.drop(columns=['_id'], inplace=True)

        # Save to a specific CSV file
        filename = f"siem_{col_name}_report.csv"
        df.to_csv(filename, index=False)
        print(f"  [+] Saved {len(df)} records to {filename}")

if __name__ == "__main__":
    export_all_siem_data()
