from fastapi import FastAPI
from ml_service import generate_attack_summary

app = FastAPI()

@app.get("/attack_summary")
def attack_summary():
    return generate_attack_summary()

# Before running backend:
#   1) Make sure to create a venv, if not already, command:
#       python -m venv venv
#   2) Make sure to activate the venv, if not already, command:
#       venv\Scripts\activate
#   3) Make sure to install requirements.txt, if not already, command:
#       pip install -r requirements.txt

# To run this api, command: uvicorn main:app --reload