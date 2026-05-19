"""
train_model.py  —  SOC ML Ensemble Anomaly Detection
======================================================
WHAT THIS DOES:
  1. Reads features.csv  (per-user features from features.py)
  2. Runs three models:
       - Isolation Forest   (unsupervised anomaly detection)
       - One-Class SVM      (boundary-based anomaly detection)
       - Rule Engine        (SOC heuristic rules)
  3. Ensemble voting: 2-of-3 = confirmed anomaly
  4. Poisoning/evasion detection
  5. Risk classification:  CRITICAL / HIGH / MEDIUM / LOW
  6. Confidence score calculation
  7. Saves  final_output.csv  (per-user ML results)

WHY THE ORIGINAL WAS BROKEN:
  - Risk classification ignored the collector's own HIGH/CRITICAL status
  - New features (cmd_events, log_cleared, svc_events) were missing
  - final_output.csv was being used by convert_to_json.py directly,
    but it has no timestamp/process/source_ip — only user summaries

FIX:
  - worst_collector_status from features.csv is now factored into risk
  - All new feature columns are included in the model
  - final_output.csv now stores ML verdict per user (not individual logs)
  - convert_to_json.py reads raw_logs.csv + merges ML results

USAGE:
  python train_model.py
"""

import os
import sys
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler

# ── Paths ─────────────────────────────────────────────────────────────────────
FEATURES_CSV    = "features.csv"
FINAL_OUTPUT    = "final_output.csv"

# ── ML Feature columns used for training ─────────────────────────────────────
# These must match exactly what features.py produces
ML_FEATURES = [
    "failed_login",
    "success_login",
    "process_events",
    "network_events",
    "dns_events",
    "file_events",
    "svc_events",
    "log_cleared",
    "cmd_events",
    "collector_high",
    "login_failure_ratio",
    "activity_score",
    "suspicion_score",
]


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                         LOAD & VALIDATE DATA                               ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

if not os.path.exists(FEATURES_CSV):
    print(f"[ERROR] {FEATURES_CSV} not found. Run features.py first.")
    sys.exit(1)

df = pd.read_csv(FEATURES_CSV, dtype=str)

# Ensure all ML feature columns exist (backfill if features.py added new ones)
for col in ML_FEATURES:
    if col not in df.columns:
        df[col] = "0"

# Convert to numeric — all ML columns must be float
df[ML_FEATURES] = df[ML_FEATURES].apply(pd.to_numeric, errors="coerce").fillna(0)

# Carry worst_collector_status (string column from features.py)
if "worst_collector_status" not in df.columns:
    df["worst_collector_status"] = "LOW"
df["worst_collector_status"] = df["worst_collector_status"].fillna("LOW").str.upper()

print("=" * 55)
print("  SOC ENSEMBLE ML MODEL")
print("=" * 55)
print(f"\n  Loaded {len(df)} user rows from {FEATURES_CSV}")
print(f"  Features: {ML_FEATURES}\n")

X = df[ML_FEATURES]


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                         SCALING                                            ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

scaler   = StandardScaler()
X_scaled = scaler.fit_transform(X)


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                      MODEL 1 — ISOLATION FOREST                            ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

# contamination = expected fraction of anomalies in data
# Lower contamination = stricter (fewer anomalies detected)
iso_model = IsolationForest(
    contamination=0.15,
    n_estimators=200,
    random_state=42,
    max_samples="auto",
)
df["iso_pred"] = iso_model.fit_predict(X_scaled)
# -1 = anomaly → convert to 1;  1 = normal → convert to 0
df["iso_pred"] = (df["iso_pred"] == -1).astype(int)

iso_anomalies = df["iso_pred"].sum()
print(f"[MODEL 1] Isolation Forest  →  {iso_anomalies}/{len(df)} anomalies detected")


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                       MODEL 2 — ONE-CLASS SVM                              ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

# nu = upper bound on fraction of outliers
svm_model = OneClassSVM(
    nu=0.15,
    kernel="rbf",
    gamma="scale",
)
df["svm_pred"] = svm_model.fit_predict(X_scaled)
df["svm_pred"] = (df["svm_pred"] == -1).astype(int)

svm_anomalies = df["svm_pred"].sum()
print(f"[MODEL 2] One-Class SVM     →  {svm_anomalies}/{len(df)} anomalies detected")


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                      MODEL 3 — SOC RULE ENGINE                             ║
# ╚══════════════════════════════════════════════════════════════════════════════╝
# Explicit heuristic rules based on known attack indicators.
# This is the "expert knowledge" component of the ensemble.

def rule_engine(row) -> int:
    score = 0

    # Authentication anomalies
    if row["failed_login"] >= 3:          score += 1   # brute force signal
    if row["failed_login"] >= 10:         score += 2   # strong brute force
    if row["login_failure_ratio"] > 0.3:  score += 1   # high failure rate

    # Network reconnaissance
    if row["network_events"] >= 3:        score += 1
    if row["network_events"] >= 10:       score += 1

    # DNS activity (tunnelling / C2 beacon)
    if row["dns_events"] >= 5:            score += 1
    if row["dns_events"] >= 20:           score += 1

    # Command-line recon / download tools
    if row["cmd_events"] >= 1:            score += 2   # any flagged command is suspicious

    # Persistence mechanisms
    if row["svc_events"] >= 1:            score += 2   # new service = persistence
    if row["log_cleared"] >= 1:           score += 5   # log clearing = CRITICAL IOC

    # Collector already flagged HIGH/CRITICAL — trust it
    if row["collector_high"] >= 1:        score += 3

    # High overall activity
    if row["activity_score"] > 100:       score += 1

    return 1 if score >= 2 else 0


df["rule_pred"] = df.apply(rule_engine, axis=1)
rule_anomalies = df["rule_pred"].sum()
print(f"[MODEL 3] Rule Engine       →  {rule_anomalies}/{len(df)} anomalies detected")


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                      ENSEMBLE VOTING (2-of-3)                              ║
# ╚══════════════════════════════════════════════════════════════════════════════╝
# ensemble_score:
#   0 = all normal     → LOW
#   1 = one flag       → suspicious (MEDIUM)
#   2 = two or more    → confirmed anomaly (HIGH)
#   3 = all three flag → maximum confidence anomaly (HIGH/CRITICAL)

def ensemble_vote(row) -> int:
    return int(row["iso_pred"]) + int(row["svm_pred"]) + int(row["rule_pred"])

df["ensemble_score"] = df.apply(ensemble_vote, axis=1)

print(f"\n  Ensemble results:")
for score in [3, 2, 1, 0]:
    count = (df["ensemble_score"] == score).sum()
    label = {3: "All 3 models flagged", 2: "2 models flagged  ",
             1: "1 model flagged   ", 0: "No flags          "}.get(score, "")
    print(f"    {label}  →  {count} users")


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                  ADVERSARIAL POISONING / EVASION DETECTION                 ║
# ╚══════════════════════════════════════════════════════════════════════════════╝
# Detects cases where a model was likely evaded or data poisoned.

def detect_poisoning(row) -> int:
    votes = int(row["iso_pred"]) + int(row["svm_pred"]) + int(row["rule_pred"])

    # Strong model disagreement = possible evasion attempt
    # (one model flags, others don't — adversary tuned behaviour to evade some)
    if votes == 1:
        # But only flag as poison if there are concrete IOCs
        if (row["cmd_events"] >= 1 or
                row["log_cleared"] >= 1 or
                row["collector_high"] >= 3):
            return 1

    # High activity that Isolation Forest missed = possible poisoning of training data
    if row["activity_score"] > 80 and row["iso_pred"] == 0 and row["rule_pred"] == 1:
        return 1

    # Log clearing + any model disagreement is always a poison flag
    if row["log_cleared"] >= 1 and votes < 3:
        return 1

    return 0


df["poison_flag"] = df.apply(detect_poisoning, axis=1)
poison_count = df["poison_flag"].sum()
print(f"\n  Adversarial/Evasion flags  →  {poison_count} users")


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                         RISK CLASSIFICATION                                ║
# ╚══════════════════════════════════════════════════════════════════════════════╝
# Combines ML ensemble result WITH the collector's original rule-based status.
# This is the critical fix — the original train_model.py ignored the collector's
# HIGH/CRITICAL status entirely, causing HIGH events to show as LOW on dashboard.

COLLECTOR_PRIORITY = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}

def risk_level(row) -> str:
    # ── Step 1: ML-based classification ──────────────────────────────────────
    if row["poison_flag"] == 1 or row["ensemble_score"] == 3:
        ml_risk = "CRITICAL"
    elif row["ensemble_score"] == 2:
        ml_risk = "HIGH"
    elif row["ensemble_score"] == 1:
        ml_risk = "MEDIUM"
    else:
        ml_risk = "LOW"

    # ── Step 2: Collector's worst raw status (from log collector rules) ───────
    collector_risk = str(row.get("worst_collector_status", "LOW")).upper()
    if collector_risk not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        collector_risk = "LOW"

    # ── Step 3: Take the WORSE of the two ────────────────────────────────────
    # A HIGH from the collector means a real high-severity event was seen.
    # Never downgrade it just because the ML model didn't flag the user.
    ml_prio        = COLLECTOR_PRIORITY.get(ml_risk,        0)
    collector_prio = COLLECTOR_PRIORITY.get(collector_risk, 0)

    return ml_risk if ml_prio >= collector_prio else collector_risk


df["risk"] = df.apply(risk_level, axis=1)

risk_counts = df["risk"].value_counts()
print(f"\n  Final risk distribution:")
for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
    print(f"    {level:<10}  {risk_counts.get(level, 0):>4} users")


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                         CONFIDENCE SCORE                                   ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

def confidence_score(row) -> float:
    base = float(row["suspicion_score"]) * 2.5

    # Boost for ensemble agreement
    if row["ensemble_score"] == 3:   base += 35
    elif row["ensemble_score"] == 2: base += 20
    elif row["ensemble_score"] == 1: base += 10

    # Boost for adversarial detection
    if row["poison_flag"] == 1:      base += 25

    # Boost if collector originally flagged HIGH/CRITICAL
    cstatus = str(row.get("worst_collector_status", "LOW")).upper()
    if cstatus == "CRITICAL":        base += 30
    elif cstatus == "HIGH":          base += 15

    return round(min(float(base), 100.0), 1)


df["confidence"] = df.apply(confidence_score, axis=1)


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                    RBAC + RESPONSE ENGINE                                  ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

def assign_role(row) -> str:
    return {"CRITICAL": "ADMIN_ONLY",
            "HIGH":     "SOC_ANALYST",
            "MEDIUM":   "SOC_ANALYST"}.get(row["risk"], "VIEWER")


def response_action(row) -> str:
    return {"CRITICAL": "BLOCK USER + ALERT ADMIN + ISOLATE MACHINE",
            "HIGH":     "INVESTIGATE USER + MONITOR NETWORK",
            "MEDIUM":   "MONITOR CLOSELY + COLLECT EVIDENCE"}.get(
        row["risk"], "NO ACTION REQUIRED"
    )


df["access_level"] = df.apply(assign_role,       axis=1)
df["response"]     = df.apply(response_action,   axis=1)


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                           SAVE OUTPUT                                      ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

output_cols = [
    "user",
    "failed_login", "success_login", "process_events",
    "network_events", "dns_events", "file_events",
    "svc_events", "log_cleared", "cmd_events", "collector_high",
    "login_failure_ratio", "activity_score", "suspicion_score",
    "worst_collector_status",
    "iso_pred", "svm_pred", "rule_pred",
    "ensemble_score", "poison_flag",
    "risk", "confidence", "access_level", "response",
]

df[output_cols].to_csv(FINAL_OUTPUT, index=False)

print(f"\n✅ {FINAL_OUTPUT} saved ({len(df)} rows)")
print("\n  Per-user ML results:")
print(df[["user", "risk", "confidence", "ensemble_score",
          "worst_collector_status", "response"]].to_string(index=False))
print(f"\n🔥 ADVANCED SOC ENSEMBLE MODEL COMPLETE")
print(f"   → Next step: python convert_to_json.py")
