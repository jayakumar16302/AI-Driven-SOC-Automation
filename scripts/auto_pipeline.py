import os
import time

while True:
    print("🔄 Running SOC pipeline...")

    os.system("python process_logs.py")
    os.system("python clean_data.py")
    os.system("python features.py")
    os.system("python train_model.py")

    print("✅ Updated model output")

    time.sleep(10)
