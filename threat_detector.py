# Anomalous activity detection logic — **written by** github: sogars  
# this script identifies suspicious activity based on the alert's volume/size, location, & known malicious indicators  
# my comments reflect real-world logic, detection edge cases, and my mindset.

import csv

# using sample trusted usernames to avoid file dependency in this demo version  
# in real-world environments you would pull from a secure file. LDAP, or have all users on a CSV, so you do not 
#have to keep editing the code 
trusted_users = ["jdoe", "sysadmin", "trusteduser123"]

# define the function to triage any alert  
def triage_alert(log_entry):
    # Case 1: high-risk scenario (large exfil + foreign + confirmed bad ip)  
    if (
        log_entry["volume_MB"] > 5000
        and log_entry["geo_location"] != "United States"
        and log_entry["known_malicious"] == "True"
    ):
        return "escalate to security engineer"

    # case 2 — this matters because high-volume alerts inside the u.s.
    # can still be malicious (insider threat, domestic APTs, or trusted IP abuse)  
    elif (
        log_entry["volume_MB"] > 5000
        and log_entry["geo_location"] == "United States"
        and log_entry["known_malicious"] == "True"
    ):
        return "alert — high volume, domestic malicious activity"

    # case 3 — hybrid logic: low-volume foreign OR any known malicious indicator  
    # this is to reduce false positives (like legit users sending w2s to themselves)  
    # but still catch beaconing + bad IPs even at small scale  
    elif (
        (log_entry["volume_MB"] < 5000 and log_entry["geo_location"] != "United States")
        or log_entry["known_malicious"] == "True"
    ) and log_entry["username"] not in trusted_users:
        return "alert — malicious low-volume or known threat"

    # case 4 — small ping from within the u.s. from an untrusted user  
    # can catch slowly beaconing out --prior conditions leave this out 
    #adjusted a few times to fine tune for false positives or misses like this.
    elif (
        log_entry["volume_MB"] < 5000
        and log_entry["geo_location"] == "United States"
        and log_entry["username"] not in trusted_users
    ):
        return "alert — suspicious low-volume from untrusted internal user"

    # catch-all — just because it didn’t meet known flags doesn’t mean it’s safe  
    # logs anything that didn’t meet criteria above for manual review  
    else:
        return "log for review"

# read in csv file (sample alert logs) and run triage logic line by line  
with open("sample_logs.csv", mode="r") as file:
    reader = csv.DictReader(file)
    for row in reader:
        # csv reads all values as strings — convert volume to int manually  
        row["volume_MB"] = int(row["volume_MB"])
        result = triage_alert(row)
        print(f"user: {row['username']} | location: {row['geo_location']} → {result}")
