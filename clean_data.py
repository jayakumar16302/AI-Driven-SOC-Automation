import pandas as pd

df = pd.read_csv("structured_logs.csv")

print("Before cleaning:", df.shape)

# --- FIX COLUMN NAMES ---
df.columns = df.columns.str.strip()

# --- HANDLE MISSING ---
df = df.fillna("Unknown")

# --- ENSURE EventID EXISTS ---
if "EventID" not in df.columns:
    raise ValueError("❌ EventID column missing")

df["EventID"] = pd.to_numeric(df["EventID"], errors="coerce").fillna(0)

# --- FILTER IMPORTANT EVENTS ---
important_ids = [4625, 4624, 1, 3, 22]
df = df[df["EventID"].isin(important_ids)]

# --- CLEAN TEXT ---
for col in ["action", "log_type", "user"]:
    if col in df.columns:
        df[col] = df[col].astype(str).str.strip()

# --- TIMESTAMP ---
df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

# --- SOC INTELLIGENCE 🔥 ---
def get_severity(event_id):
    if event_id == 4625:
        return "HIGH"
    elif event_id == 3:
        return "MEDIUM"
    elif event_id == 22:
        return "MEDIUM"
    elif event_id == 1:
        return "LOW"
    else:
        return "INFO"

df["severity"] = df["EventID"].apply(get_severity)

# --- RISK ---
def get_risk(action):
    if "Failed Login" in action:
        return "HIGH"
    elif "Network Connection" in action:
        return "SUSPICIOUS"
    elif "DNS Query" in action:
        return "SUSPICIOUS"
    else:
        return "NORMAL"

df["risk"] = df["action"].apply(get_risk)

# --- TIME FEATURES ---
df["date"] = df["timestamp"].dt.date
df["hour"] = df["timestamp"].dt.hour

# --- REMOVE DUPLICATES ---
df = df.drop_duplicates()

# --- SAVE ---
df.to_csv("clean_logs.csv", index=False)

print("After cleaning:", df.shape)
print("✅ Clean logs ready!")