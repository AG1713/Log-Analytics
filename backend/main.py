from fastapi import FastAPI
from ml_service import generate_attack_summary

app = FastAPI()

@app.get("/attack_summary")
def attack_summary():
    return generate_attack_summary()