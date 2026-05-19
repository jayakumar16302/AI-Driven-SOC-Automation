"""
features.py  —  SOC Feature Engineering
========================================
WHAT THIS DOES:
  1. Reads data.json  (all individual log records from the VM collector)
  2. Generates per-user ML feature rows  →  features.csv
     (used by train_model.py for Isolation Forest + SVM)
  3. ALSO saves a clean copy of all individual logs  →  raw_logs.csv
     (used by convert_to_json.py to produce the final dashboard data.json)

WHY THE ORIGINAL WAS BROKEN:
  - features.py was collapsing 2800 records into 25 user-summary rows
  - That 25-row file was then converted to data.json → dashboard showed 25 events
  - The original status/HIGH/CRITICAL from individual logs was completely lost
  - timestamp, source_ip, process, commandline were all lost in aggregation

FIX:
  - features.csv  = per-user aggregated rows  (ML training input)
  - raw_logs.csv  = all individual log records (dashboard output source)

USAGE:
  python features.py
"""

import json
import os
import pandas as pd

# ── Paths ─────────────────────────────────────────────────────────────────────
INPUT_JSON   = "data.json"       # raw logs from VM collector
FEATURES_CSV = "features.csv"   # per-user ML features (→ train_model.py)
RAW_LOGS_CSV = "raw_logs.csv"   # all individual records (→ convert_to_json.py)

# ── Status/risk priority for carrying the worst per-user status ───────────────
STATUS_PRIORITY = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}


def load_logs() -> list[dict]:
    """Load data.json. Supports both array [ {...} ] and object { "logs": [...] }."""
    if not os.path.exists(INPUT_JSON):
        print(f"[ERROR] {INPUT_JSON} not found. Run the VM log collector first.")
        raise SystemExit(1)

    with open(INPUT_JSON, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("logs") or data.get("data") or list(data.values())[0]

    print("[ERROR] Unexpected data.json format.")
    raise SystemExit(1)


def save_raw_logs(df: pd.DataFrame) -> None:
    """
    Save ALL individual log records to raw_logs.csv.
    This is the file convert_to_json.py must read — NOT final_output.csv —
    so every event row (with timestamp, source_ip, process, etc.) is preserved.
    """
    df.to_csv(RAW_LOGS_CSV, index=False)
    print(f"  [raw_logs.csv]  {len(df)} individual records saved")


def generate_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Aggregate individual log records into one feature row per user.
    These features are used exclusively for ML anomaly detection.

    Features extracted:
      failed_login         — count of EventID 4625
      success_login        — count of EventID 4624
      process_events       — count of EventID 1  (process creation)
      network_events       — count of EventID 3  (network connection)
      dns_events           — count of EventID 22 (DNS query)
      high_status_events   — count of raw status = HIGH or CRITICAL from collector
      login_failure_ratio  — failed / total logins
      activity_score       — total events for this user
      suspicion_score      — weighted heuristic score

    NOTE: status/risk is derived by train_model.py — not carried here.
    """
    # Normalise types
    df = df.copy()
    df["event_id"] = df["event_id"].astype(str).str.strip()
    df["user"]     = df["user"].fillna("unknown").astype(str).str.strip()
    df["status"]   = df.get("status", pd.Series(["LOW"] * len(df))).fillna("LOW")

    # Detect command-based HIGH events from commandline field
    cmd_col = df.get("commandline", pd.Series([""] * len(df))).fillna("").str.upper()
    CMD_KEYWORDS = ("PING ", "CURL ", "NSLOOKUP", "TRACERT", "WGET ",
                    "INVOKE-WEBREQUEST", "IWR ", "NET USER", "WHOAMI",
                    "MIMIKATZ", "PROCDUMP", "PSEXEC")
    df["_cmd_flag"] = cmd_col.apply(
        lambda c: 1 if any(kw in c for kw in CMD_KEYWORDS) else 0
    )

    feature_rows = []

    for user, user_df in df.groupby("user", sort=False):
        eids = user_df["event_id"]

        failed_login   = (eids == "4625").sum()
        success_login  = (eids == "4624").sum()
        process_events = (eids == "1").sum()
        network_events = (eids == "3").sum()
        dns_events     = (eids == "22").sum()
        file_events    = (eids == "11").sum()
        svc_events     = (eids == "7045").sum()
        log_cleared    = (eids == "104").sum()
        cmd_events     = user_df["_cmd_flag"].sum()

        # Count events the collector already flagged HIGH or CRITICAL
        collector_high = user_df["status"].isin(["HIGH", "CRITICAL"]).sum()

        total_logins        = failed_login + success_login
        login_failure_ratio = failed_login / total_logins if total_logins > 0 else 0
        activity_score      = len(user_df)

        suspicion_score = (
            failed_login        * 3.0 +
            network_events      * 2.0 +
            dns_events          * 1.5 +
            process_events      * 0.5 +
            cmd_events          * 4.0 +   # command-based activity is highly suspicious
            svc_events          * 3.0 +
            log_cleared         * 10.0 +  # log clearing is a critical IOC
            collector_high      * 2.0
        )

        # Carry the worst raw status seen for this user from the collector
        # This bridges the collector's rule-based classification into the ML pipeline
        statuses   = user_df["status"].str.upper()
        worst_prio = statuses.map(lambda s: STATUS_PRIORITY.get(s, 0)).max()
        worst_status = next(
            (k for k, v in sorted(STATUS_PRIORITY.items(), key=lambda x: -x[1])
             if v <= worst_prio), "LOW"
        )

        feature_rows.append({
            "user":                user,
            "failed_login":        int(failed_login),
            "success_login":       int(success_login),
            "process_events":      int(process_events),
            "network_events":      int(network_events),
            "dns_events":          int(dns_events),
            "file_events":         int(file_events),
            "svc_events":          int(svc_events),
            "log_cleared":         int(log_cleared),
            "cmd_events":          int(cmd_events),
            "collector_high":      int(collector_high),
            "login_failure_ratio": round(float(login_failure_ratio), 4),
            "activity_score":      int(activity_score),
            "suspicion_score":     round(float(suspicion_score), 2),
            "worst_collector_status": worst_status,  # passed to train_model.py
        })

    return pd.DataFrame(feature_rows)


def main():
    print("=" * 55)
    print("  SOC FEATURE ENGINEERING")
    print("=" * 55)

    print(f"\n[1/3] Loading {INPUT_JSON}...")
    logs = load_logs()
    print(f"      Loaded {len(logs)} individual log records")

    print("\n[2/3] Building dataframe...")
    df = pd.DataFrame(logs)

    # Ensure essential columns exist even if collector didn't produce them
    for col in ["event_id", "user", "status", "timestamp", "process",
                "source_ip", "commandline", "dns_query", "log_type",
                "event_type", "logon_type"]:
        if col not in df.columns:
            df[col] = "N/A"

    # Save raw individual logs BEFORE any aggregation
    print("\n[3/3] Saving outputs...")
    save_raw_logs(df)

    features_df = generate_features(df)
    features_df.to_csv(FEATURES_CSV, index=False)
    print(f"  [features.csv]  {len(features_df)} user-feature rows saved")

    print("\n  User summary:")
    for _, row in features_df.sort_values("suspicion_score", ascending=False).iterrows():
        print(f"    {row['user']:<25}  "
              f"suspicion={row['suspicion_score']:>6.1f}  "
              f"activity={row['activity_score']:>4}  "
              f"worst_status={row['worst_collector_status']}")

    print(f"\n✅ Feature engineering complete.")
    print(f"   → {FEATURES_CSV}  (input for train_model.py)")
    print(f"   → {RAW_LOGS_CSV}  (input for convert_to_json.py)")


if __name__ == "__main__":
    main()
