import pandas as pd
import joblib
import json
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Cargar modelo y columnas
model = joblib.load("rf_model_nsl_kdd.pkl")
with open("columns.json", "r") as f:
    model_columns = json.load(f)

@app.post("/predict")
def predict(data: dict):
    df = pd.DataFrame([data])

    # 🔹 Añadir columnas faltantes con 0
    for col in model_columns:
        if col not in df.columns:
            df[col] = 0

    # 🔹 Reordenar columnas como en el entrenamiento
    df = df[model_columns]

    prediction = model.predict(df)[0]
    return {"prediction": int(prediction)}
