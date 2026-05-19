import pandas as pd

df = pd.read_csv("final_output.csv")

alerts = []

for index, row in df.iterrows():
    user = row.get("user", "unknown")
    risk = row.get("risk", "LOW")
    confidence = row.get("confidence", 0)

    if risk == "HIGH":
        message = f"[ALERT] High risk user: {user} → BLOCK / ISOLATE"
        action = "BLOCK"
    elif risk == "MEDIUM":
        message = f"[WARNING] Suspicious user: {user} → ALERT ADMIN"
        action = "MONITOR"
    else:
        message = f"[INFO] Normal activity: {user}"
        action = "ALLOW"

    print(message)

    # 🔥 STORE FOR DASHBOARD
    alerts.append({
        "user": user,
        "risk": risk,
        "confidence": confidence,
        "action": action,
        "message": message
    })

# 🔥 SAVE ALERTS FILE
alerts_df = pd.DataFrame(alerts)
alerts_df.to_csv("alerts.csv", index=False)

print("\n✅ Alerts generated and saved to alerts.csv")
