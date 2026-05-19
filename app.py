from flask import Flask, jsonify
from flask_cors import CORS
import pandas as pd

app = Flask(__name__)
CORS(app)   # 🔥 allow frontend access


# 🔥 STATUS MAPPING (CRITICAL FIX)
def map_status(row):
    action = str(row.get("action", "")).lower()
    risk   = str(row.get("risk", "LOW")).upper()

    # 🔴 Critical conditions
    if "failed login" in action:
        return "CRITICAL"

    # 🟠 Suspicious / medium → HIGH
    elif risk in ["SUSPICIOUS", "MEDIUM"]:
        return "HIGH"

    # 🟢 Normal
    else:
        return "LOW"


@app.route("/data")
def get_data():
    try:
        # 🔥 USE ENRICHED LOGS (EVENT LEVEL DATA)
        df = pd.read_csv("enriched_logs.csv")

        # 🔥 Ensure latest logs first
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
            df = df.sort_values(by="timestamp", ascending=False)

        # 🔥 LIMIT FOR DASHBOARD (performance)
        df = df.head(1000000000)

        data = []

        for _, row in df.iterrows():
            data.append({
                "timestamp": str(row.get("timestamp", "LIVE")),
                "event_type": row.get("action", "Activity"),
                "user": row.get("user", "system"),
                "process": row.get("process_name", "-"),
                "source_ip": row.get("source_ip", "-"),

                # 🔥 MAIN FIX (IMPORTANT)
                "status": map_status(row),

                # 🔥 CONFIDENCE (fallback safe)
                "confidence_score": float(row.get("confidence", 50))
            })

        return jsonify(data)

    except Exception as e:
        print("❌ ERROR:", e)
        return jsonify([])


if __name__ == "__main__":
    app.run(debug=True)