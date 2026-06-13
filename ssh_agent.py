import re
import json
from collections import defaultdict
from datetime import datetime

LOG_FILE = "/var/log/auth.log"

attack_data = defaultdict(lambda: {
    "attempts": 0,
    "timestamps": [],
    "usernames": set(),
    "success": False
})

with open(LOG_FILE, "r", errors="ignore") as file:

    for line in file:

        # Failed login detection
        if "Failed password" in line:

            ip_match = re.search(
                r'from (\d+\.\d+\.\d+\.\d+)', line)

            user_match = re.search(
                r'Failed password for (?:invalid user )?(\S+)', line)

            time_match = re.match(
                r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})',
                line
            )

            if ip_match:

                ip = ip_match.group(1)

                attack_data[ip]["attempts"] += 1

                if user_match:
                    attack_data[ip]["usernames"].add(
                        user_match.group(1))

                if time_match:
                    timestamp = datetime.strptime(
                        time_match.group(1),
                        "%Y-%m-%dT%H:%M:%S"
                    )

                    attack_data[ip]["timestamps"].append(timestamp)

        # Successful login detection
        elif "Accepted password" in line:

            ip_match = re.search(
                r'from (\d+\.\d+\.\d+\.\d+)', line)

            if ip_match:

                ip = ip_match.group(1)

                if ip in attack_data:
                    attack_data[ip]["success"] = True

results = []

for ip, data in attack_data.items():

    attempts = data["attempts"]
    usernames = len(data["usernames"])
    success = data["success"]

    timestamps = sorted(data["timestamps"])

    score = 0

    # Rule 1: Failed Attempts
    if attempts >= 5:
        score += 2

    if attempts >= 10:
        score += 3

    if attempts >= 20:
        score += 5

    # Rule 2: Multiple Usernames
    if usernames >= 3:
        score += 4

    # Rule 3: Rapid Attempts
    rapid_attempts = 0

    for i in range(1, len(timestamps)):

        diff = (
            timestamps[i] -
            timestamps[i - 1]
        ).total_seconds()

        if diff <= 1:
            rapid_attempts += 1

    if rapid_attempts >= 5:
        score += 5

    # Rule 4: Success after failures
    if success:
        score += 6

    # Risk Level
    if score >= 12:
        risk = "HIGH"
    elif score >= 6:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    results.append({
        "ip": ip,
        "attempts": attempts,
        "usernames": usernames,
        "rapid_attempts": rapid_attempts,
        "success_after_failure": success,
        "risk_score": score,
        "risk_level": risk
    })

print(json.dumps(results, indent=4))
