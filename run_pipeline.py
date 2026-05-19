import os
import time

while True:
    print("\n🚀 Running SOC Pipeline...\n")

    os.system("python process_logs.py")
    os.system("python clean_data.py")
    os.system("python features.py")
    os.system("python train_model.py")
    os.system("python convert_to_json.py")

    print("✅ Pipeline complete — updating dashboard...\n")

    time.sleep(10)   # every 10 seconds