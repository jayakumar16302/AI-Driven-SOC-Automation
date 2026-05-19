import pandas as pd

df = pd.read_csv("results.csv")

# --- NORMALIZE SCORE TO 0–100 ---
max_score = df["score"].max()

if max_score == 0:
    df["confidence"] = 0
else:
    df["confidence"] = (df["score"] / max_score) * 100

# --- RISK LEVEL ---
def risk_level(c):
    if c > 80:
        return "HIGH"
    elif c > 50:
        return "MEDIUM"
    else:
        return "LOW"

df["risk"] = df["confidence"].apply(risk_level)

# --- SAVE ---
df.to_csv("final_output.csv", index=False)

print("✅ Confidence scoring done!")
print(df.head())
