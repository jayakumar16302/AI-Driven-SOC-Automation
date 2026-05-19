import pandas as pd
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

log_files = [
    "sysmon1st.evtx",
    "seclogs1st.evtx",
    "systemlogs1st.evtx"
]

events = []

# --- Extract EventID ---
def get_event_id(root):
    for elem in root.iter():
        if "EventID" in elem.tag:
            try:
                return int(elem.text)
            except:
                return None
    return None

# --- Extract Time ---
def get_time(root):
    for elem in root.iter():
        if "TimeCreated" in elem.tag:
            return elem.attrib.get("SystemTime", "Unknown")
    return "Unknown"

# --- Extract User ---
def get_user(root):
    for elem in root.iter():
        if "TargetUserName" in elem.tag or "SubjectUserName" in elem.tag:
            if elem.text and elem.text.strip():
                return elem.text
    return "system"

# --- Assign Action ---
def get_action(event_id, log_file):
    if "sysmon" in log_file.lower():
        if event_id == 1:
            return "Process Created"
        elif event_id == 3:
            return "Network Connection"
        elif event_id == 22:
            return "DNS Query"
        else:
            return "Sysmon Activity"

    elif "sec" in log_file.lower():
        if event_id == 4625:
            return "Failed Login"
        elif event_id == 4624:
            return "Successful Login"
        else:
            return "Security Activity"

    else:
        return "System Activity"

# --- Assign Risk ---
def assign_risk(action):
    if "Failed Login" in action:
        return "HIGH"
    elif "Network Connection" in action:
        return "SUSPICIOUS"
    elif "DNS Query" in action:
        return "SUSPICIOUS"
    elif "Process Created" in action:
        return "LOW"
    else:
        return "NORMAL"

# --- MAIN PROCESS ---
for log_file in log_files:
    print(f"Reading {log_file}...")

    with Evtx(log_file) as log:
        for record in log.records():
            try:
                xml = record.xml()
                root = ET.fromstring(xml)

                event_id = get_event_id(root)
                if event_id is None:
                    continue

                time = get_time(root)
                user = get_user(root)
                action = get_action(event_id, log_file)

                events.append({
                    "timestamp": time,
                    "log_type": log_file,
                    "EventID": event_id,
                    "user": user,
                    "action": action
                })

            except Exception as e:
                continue

# --- CREATE DATAFRAME ---
df = pd.DataFrame(events)

# --- ADD RISK ---
df["risk"] = df["action"].apply(assign_risk)

# --- SAVE OUTPUT ---
df.to_csv("structured_logs.csv", index=False)

print("\n✅ Structured logs created successfully!")
print(df.head())
