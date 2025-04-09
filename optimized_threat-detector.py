import csv
from datetime import datetime
import numpy as np
from scipy import stats

# Sample trusted users for the demo
trusted_users = ["jdoe", "sysadmin", "trusteduser123"]

# List to collect timestamps for interval logic
login_times = []

# Detection logic with timing and behavior context
def triage_alert(log_entry):
    # Support both timestamp formats
    try:
        login_time = datetime.strptime(log_entry["timestamp"], "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        login_time = datetime.strptime(log_entry["timestamp"], "%Y-%m-%dT%H:%M:%SZ")
    
    login_times.append(login_time)

    # Calculate login interval score if we have enough timestamps
    login_interval_score = 0
    if len(login_times) > 2:
        intervals = [
            (login_times[i + 1] - login_times[i]).total_seconds()
            for i in range(len(login_times) - 1)
        ]
        z_scores = np.abs(stats.zscore(intervals))
        login_interval_score = z_scores[-1]  # score of the latest interval

    if (
        log_entry["volume_MB"] > 5000
        and log_entry["geo_location"] != "United States"
        and log_entry["known_malicious"] == "True"
    ):
        return "escalate to security engineer"
    elif (
        log_entry["volume_MB"] > 5000
        and log_entry["geo_location"] == "United States"
        and log_entry["known_malicious"] == "True"
    ):
        return "alert – high volume, domestic malicious activity"
    elif (
        (log_entry["volume_MB"] < 5000 and log_entry["geo_location"] != "United States")
        or log_entry["known_malicious"] == "True"
    ) and log_entry["username"] not in trusted_users:
        return "alert – malicious low-volume or known threat"
    elif (
        log_entry["volume_MB"] < 5000
        and log_entry["geo_location"] == "United States"
        and log_entry["username"] not in trusted_users
    ):
        return "alert – suspicious low-volume from untrusted internal user"
    elif login_interval_score > 2.5 and log_entry["username"] not in trusted_users:
        return "alert – suspicious login timing anomaly"
    else:
        return "log for review"

# Load and process CSV logs
with open("sample_logs.csv", mode="r") as file:
    reader = csv.DictReader(file)
    for row in reader:
        row["volume_MB"] = int(row["volume_MB"])
        result = triage_alert(row)
        print(f"user: {row['username']} | location: {row['geo_location']} → {result}")
