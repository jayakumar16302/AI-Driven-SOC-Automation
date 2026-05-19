"""
convert_to_json.py  —  SOC Dashboard JSON Generator
=====================================================
WHAT THIS DOES:
  1. Reads raw_logs.csv        (all individual log records — from features.py)
  2. Reads final_output.csv    (per-user ML risk results — from train_model.py)
  3. Merges ML risk/confidence onto every individual log row by username
  4. Writes data.json          (dashboard-ready, all individual events preserved)

WHY THE ORIGINAL WAS BROKEN:
  - convert_to_json.py was reading final_output.csv which only has 25 user rows
  - It produced a data.json with 25 records instead of 2800
  - timestamp, source_ip, process, commandline were all "N/A" because
    final_output.csv (user aggregates) never had those columns
  - The dashboard "status" field was never set because the script saved
    "risk" but the dashboard reads "status"
  - HIGH events from the collector were silently dropped

FIX:
  - Read raw_logs.csv (all individual events with all fields intact)
  - Join ML result (risk, confidence, response) onto each row by user
  - Set "status" = ML risk (or collector status if ML didn't flag it)
  - Smart sampling: 80% real users, 20% SYSTEM in the final JSON
  - Output all 200 (configurable) records with full field set

CORRECT PIPELINE ORDER:
  python features.py          →  creates features.csv + raw_logs.csv
  python train_model.py       →  creates final_output.csv
  python convert_to_json.py   →  creates data.json  (dashboard reads this)

USAGE:
  python convert_to_json.py
"""

import json
import os
import sys
import csv as csv_mod
import pandas as pd

# ── Paths ─────────────────────────────────────────────────────────────────────
RAW_LOGS_CSV   = "raw_logs.csv"       # all individual log records (features.py output)
FINAL_OUTPUT   = "final_output.csv"   # per-user ML results (train_model.py output)
OUTPUT_JSON    = "data.json"          # dashboard reads this

# ── Dashboard output config ───────────────────────────────────────────────────
MAX_RECORDS        = 200    # total records in data.json
REAL_USER_FRACTION = 0.80   # 80% real users, 20% SYSTEM
MIN_SYSTEM_ROWS    = 10     # always include at least this many SYSTEM rows

# ── Status priority for merge conflict resolution ─────────────────────────────
STATUS_PRIORITY = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}


def load_csv_safe(path: str, label: str) -> pd.DataFrame:
    """Load a CSV with robust error handling."""
    if not os.path.exists(path):
        print(f"[ERROR] {path} not found.")
        if label == "raw_logs":
            print("        Run:  python features.py")
        else:
            print("        Run:  python train_model.py")
        sys.exit(1)

    try:
        df = pd.read_csv(
            path,
            dtype=str,
            quoting=csv_mod.QUOTE_ALL,
            on_bad_lines="skip",
            engine="python",
        )
        print(f"  [{label}]  {len(df)} rows loaded from {path}")
        return df
    except Exception as e:
        # Fallback: try default CSV parser (no QUOTE_ALL)
        try:
            df = pd.read_csv(path, dtype=str, on_bad_lines="skip")
            print(f"  [{label}]  {len(df)} rows loaded (fallback parser)")
            return df
        except Exception as e2:
            print(f"[ERROR] Cannot read {path}: {e2}")
            sys.exit(1)


def merge_ml_results(logs_df: pd.DataFrame, ml_df: pd.DataFrame) -> pd.DataFrame:
    """
    Join per-user ML results onto every individual log record.

    The join key is 'user'. Every row in logs_df gets the ML risk/confidence
    for that user from ml_df.

    Status resolution (per row):
      - Start with the collector's original status (from raw_logs.csv)
      - Compare with ML risk from final_output.csv
      - Take the WORSE of the two
      This ensures a row already marked HIGH by the collector stays HIGH
      even if the user's aggregate ML score was LOW.
    """
    # Normalise join key
    logs_df["user"] = logs_df["user"].fillna("unknown").astype(str).str.strip()
    ml_df["user"]   = ml_df["user"].fillna("unknown").astype(str).str.strip()

    # Select only the columns we need from final_output.csv
    ml_cols = ["user", "risk", "confidence", "response",
               "access_level", "ensemble_score", "poison_flag",
               "worst_collector_status"]
    available_ml_cols = [c for c in ml_cols if c in ml_df.columns]
    ml_subset = ml_df[available_ml_cols].drop_duplicates(subset="user")

    # Left-join: every log row keeps its fields, ML columns added on right
    merged = logs_df.merge(ml_subset, on="user", how="left")

    # Fill ML columns for users not found in final_output.csv
    for col, default in [
        ("risk",              "LOW"),
        ("confidence",        "0"),
        ("response",          "NO ACTION REQUIRED"),
        ("access_level",      "VIEWER"),
        ("ensemble_score",    "0"),
        ("poison_flag",       "0"),
        ("worst_collector_status", "LOW"),
    ]:
        if col in merged.columns:
            merged[col] = merged[col].fillna(default)
        else:
            merged[col] = default

    # ── Resolve final status per row ──────────────────────────────────────────
    # collector_status: what the log collector originally assigned
    # ml_risk:          what the ML model assigned for this user overall
    # final status:     the worse of the two

    collector_raw = merged.get("status", pd.Series(["LOW"] * len(merged))).fillna("LOW")
    ml_risk_col   = merged["risk"].str.upper()

    def resolve_status(collector: str, ml_risk: str) -> str:
        c_prio = STATUS_PRIORITY.get(collector.upper(), 0)
        m_prio = STATUS_PRIORITY.get(ml_risk.upper(),   0)
        return collector.upper() if c_prio >= m_prio else ml_risk.upper()

    merged["status"] = [
        resolve_status(c, m)
        for c, m in zip(collector_raw, ml_risk_col)
    ]

    return merged


def smart_sample(df: pd.DataFrame, n: int) -> pd.DataFrame:
    """
    Return up to n rows, prioritising real-user rows over SYSTEM rows.
    Real user fraction = REAL_USER_FRACTION (default 80%).
    Always includes at least MIN_SYSTEM_ROWS SYSTEM rows.
    """
    system_mask = df["user"].str.upper().isin(["SYSTEM", "SYSTEM_MACHINE", "N/A", "UNKNOWN"])
    real_df     = df[~system_mask]
    sys_df      = df[system_mask]

    want_real = int(n * REAL_USER_FRACTION)
    want_sys  = max(MIN_SYSTEM_ROWS, n - want_real)

    sampled_real = real_df.tail(want_real) if len(real_df) >= want_real else real_df
    sampled_sys  = sys_df.tail(want_sys)   if len(sys_df)  >= want_sys  else sys_df

    combined = pd.concat([sampled_real, sampled_sys], ignore_index=True)

    # Sort chronologically if timestamp is available
    if "timestamp" in combined.columns:
        combined = combined.sort_values("timestamp", ascending=True,
                                        na_position="first")

    return combined.tail(n)


def sanitise(v) -> str:
    """Clean a value to a single-line safe string."""
    if v is None or (isinstance(v, float) and pd.isna(v)):
        return "N/A"
    s = str(v)
    for bad in ("\r\n", "\n", "\r", "\t"):
        s = s.replace(bad, " ")
    return s.strip() or "N/A"


def build_dashboard_record(row: pd.Series) -> dict:
    """
    Convert one merged dataframe row into a dashboard JSON record.
    Field names match exactly what the SOC dashboard JavaScript reads.
    """
    # Confidence: normalise to 0.0–1.0 range for dashboard display
    try:
        conf_raw = float(row.get("confidence", 0) or 0)
        conf_normalised = round(conf_raw / 100.0, 4) if conf_raw > 1.0 else round(conf_raw, 4)
    except (ValueError, TypeError):
        conf_normalised = 0.0

    return {
        # ── Core fields the dashboard log table reads ─────────────────────────
        "timestamp":        sanitise(row.get("timestamp",   "N/A")),
        "event_type":       sanitise(row.get("event_type",  "User Activity")),
        "user":             sanitise(row.get("user",        "N/A")),
        "process": sanitise(
    str(row.get("process", "N/A")).split("\\")[-1]
),
        "source_ip":        sanitise(row.get("source_ip",   "N/A")),
        "status":           sanitise(row.get("status",      "LOW")).upper(),

        # ── Status field aliases — dashboard uses "status" not "risk" ─────────
        # Both are set so the dashboard works regardless of which field it reads
        "risk":             sanitise(row.get("status", row.get("risk", "LOW"))).upper(),

        # ── Extra fields (confidence panel, timeline, actions) ────────────────
        "event_id":         sanitise(row.get("event_id",    "")),
        "log_type":         sanitise(row.get("log_type",    "")),
        "commandline":      sanitise(row.get("commandline", "N/A")),
        "logon_type":       sanitise(row.get("logon_type",  "N/A")),
        "dns_query":        sanitise(row.get("dns_query",   "N/A")),
        "confidence_score": conf_normalised,

        # ── ML metadata ───────────────────────────────────────────────────────
        "response":         sanitise(row.get("response",      "NO ACTION REQUIRED")),
        "access_level":     sanitise(row.get("access_level",  "VIEWER")),
        "ensemble_score":   sanitise(row.get("ensemble_score","0")),
        "poison_flag":      sanitise(row.get("poison_flag",   "0")),
    }


def print_summary(records: list[dict]) -> None:
    """Print a summary of the final data.json to the terminal."""
    total    = len(records)
    critical = sum(1 for r in records if r["status"] == "CRITICAL")
    high     = sum(1 for r in records if r["status"] == "HIGH")
    medium   = sum(1 for r in records if r["status"] == "MEDIUM")
    low      = total - critical - high - medium

    system_count = sum(1 for r in records if r["user"].upper() in
                       ("SYSTEM", "SYSTEM_MACHINE", "N/A", "UNKNOWN"))
    real_count   = total - system_count

    print(f"\n  data.json summary:")
    print(f"    Total records   : {total}")
    print(f"    Real-user rows  : {real_count}")
    print(f"    SYSTEM rows     : {system_count}")
    print(f"    CRITICAL        : {critical}")
    print(f"    HIGH            : {high}")
    print(f"    MEDIUM          : {medium}")
    print(f"    LOW             : {low}")

    # Show HIGH/CRITICAL rows for verification
    flagged = [r for r in records if r["status"] in ("HIGH", "CRITICAL")]
    if flagged:
        print(f"\n  Flagged events ({len(flagged)} HIGH/CRITICAL):")
        for r in flagged[:10]:
            print(f"    [{r['status']:<8}]  "
                  f"user={r['user']:<22}  "
                  f"type={r['event_type']:<28}  "
                  f"conf={r['confidence_score']}")
    else:
        print("\n  No HIGH/CRITICAL events in output. "
              "Check your log collector is generating flagged events.")


def main():
    print("=" * 55)
    print("  SOC DASHBOARD JSON GENERATOR")
    print("=" * 55)

    # ── Step 1: load raw individual logs ─────────────────────────────────────
    print("\n[1/4] Loading individual log records...")
    logs_df = load_csv_safe(RAW_LOGS_CSV, "raw_logs")

    # ── Step 2: load ML results ───────────────────────────────────────────────
    print("\n[2/4] Loading ML results...")
    ml_df = load_csv_safe(FINAL_OUTPUT, "ml_results")

    # ── Step 3: merge ML risk onto every log row ──────────────────────────────
    print("\n[3/4] Merging ML results onto individual log rows...")
    merged_df = merge_ml_results(logs_df, ml_df)
    print(f"      {len(merged_df)} rows after merge")

    status_counts = merged_df["status"].value_counts()
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        print(f"      {level:<10} {status_counts.get(level, 0):>5} rows")

    # ── Step 4: smart sample + build JSON ────────────────────────────────────
    print(f"\n[4/4] Building dashboard JSON "
          f"(max {MAX_RECORDS} records, "
          f"{int(REAL_USER_FRACTION*100)}% real users)...")

    sampled = smart_sample(merged_df, MAX_RECORDS)
    records = [build_dashboard_record(row) for _, row in sampled.iterrows()]

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False)

    print_summary(records)

    print(f"\n✅ {OUTPUT_JSON} written  ({len(records)} records)")
    print(f"   Copy {OUTPUT_JSON} to your dashboard folder.")
    print(f"   Open soc_dashboard.html in a browser.")
    print(f"\n🔥 DASHBOARD DATA READY")


if __name__ == "__main__":
    main()
