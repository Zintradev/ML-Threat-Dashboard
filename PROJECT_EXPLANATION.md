# 📘 Complete Project Architecture Guide

This guide explains **absolutely everything** about the project: how it works, what each file does, and how data flows.

---

## 🏗️ High-Level Architecture

The system is divided into 3 main blocks that work together:

1.  **Frontend (React)**: What you see. It is the control panel (Dashboard) where charts and alerts appear.
2.  **Backend (FastAPI)**: The brain. It receives data, runs the Artificial Intelligence model, and decides if something is a threat.
3.  **Proxy (MITMProxy)**: The spy. It intercepts real internet traffic from your browser and sends it to the Backend for analysis.

### 🔄 Data Flow (The journey of a click)

1.  **User**: Browses the internet (e.g., visits a website).
2.  **Proxy**: Captures that request (URL, method, headers).
3.  **Backend**:
    *   Receives data from the Proxy.
    *   Extracts features (length, keywords, rare characters).
    *   Passes them to the **ML Model**.
    *   The model says: "Is it a threat or normal?".
4.  **Frontend**: Queries the Backend every 3 seconds and updates the on-screen charts.

---

## 📂 File Structure and Purpose

### 1. Project Root
*   `docker-compose.yml`: The blueprint. Tells Docker how to launch the Frontend and Backend together.
*   `Dockerfile.backend` / `Dockerfile.frontend`: The recipes to create the containers for each part.
*   `nginx.conf`: Configuration for the web server that serves the Frontend in production.
*   `DOCKER_SETUP.md`: Instructions for installing and using Docker.

### 2. Backend (`/backend`)
The operation's brain, written in Python.

*   **`main.py`**: **The most important file**.
    *   Starts the API server.
    *   Loads the AI model (`RealTimeMLModel`).
    *   Defines endpoints (entry points) for the Frontend and Proxy to communicate with it.
    *   Manages the traffic capture system (`TrafficCaptureSystem`).

*   **`mitmproxy_addon.py`**: The spy's "plugin".
    *   A script loaded inside MITMProxy.
    *   Every time an HTTP request passes through, this script copies it and sends it to the Backend (`/capture/request`).

*   **`train_model.py`**: The trainer.
    *   Creates synthetic data (fake but realistic) of attacks and normal traffic.
    *   Trains a `RandomForestClassifier` model.
    *   Saves the trained model to `real_traffic_model.pkl`.

*   **`real_traffic_model.pkl`**: The frozen brain. It is the binary file containing the already trained AI model ready to use.

*   **`requirements.txt`**: The shopping list. Lists the Python libraries needed (FastAPI, scikit-learn, pandas, etc.).

### 3. Frontend (`/frontend/ml-threat-dashboard`)
The visible face, written in React and TypeScript.

*   **`src/App.tsx`**: The main application container.
*   **`src/Dashboard.tsx`**: **The star component**.
    *   Draws the entire interface: charts, tables, alerts.
    *   Connects to the Backend (`axios.get`) to request new data.
    *   Shows red alerts if there are threats.
*   **`src/App.css`**: The styles. Defines the modern look, with dark mode and glassmorphism effects.
*   **`package.json`**: The Frontend shopping list. Defines JavaScript libraries (React, Chart.js, etc.).

---

## 🧠 How does Artificial Intelligence work here?

The model doesn't "read" the web like a human, but analyzes **numerical patterns**:

1.  **Feature Extraction** (in `main.py` -> `_rule_based_analysis` and model):
    *   How long is the URL?
    *   Does it have rare characters like `<` `>` `'` `"`?
    *   Does it contain dangerous words like `SELECT`, `UNION`, `SCRIPT`?
    *   Is the status code an error (404, 500)?

2.  **Prediction**:
    *   The model (Random Forest) takes those numbers and votes.
    *   If many "trees" in the forest say it's SQL Injection, it is marked as such.
    *   Calculates a **confidence** (e.g., 95% sure).

3.  **MITRE Mapping**:
    *   If an attack is detected, it looks up its ID in the MITRE ATT&CK database (e.g., SQL Injection = T1190) to provide professional context.

---

## 🐳 Why Docker?

Docker creates two isolated "boxes":
1.  **Backend Box**: Has Python installed and runs `main.py`.
2.  **Frontend Box**: Has a web server (Nginx) and serves React files.

These boxes are connected by an internal "virtual network". When you visit `localhost:3000`, your browser talks to the Frontend box, which in turn asks the Backend box for data. All clean and without messing up your Windows.
