import re
import json
import os
import requests
from datetime import datetime

LOG_FILE = "/var/log/auth.log"
STATE_FILE = "/home/ubuntu/.sshagent_state.json"
WINDOWS_URL = "http://WINDOWS_IP:5000/logs"  # <-- update with your Windows machine's IP

TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S"


def load_last_timestamp():
    if not os.path.exists(STATE_FILE):
        return None

    with open(STATE_FILE, "r") as f:
        state = json.load(f)
        ts = state.get("last_timestamp")

        if ts:
            return datetime.strptime(ts, TIMESTAMP_FORMAT)

    return None


def save_last_timestamp(timestamp):
    with open(STATE_FILE, "w") as f:
        json.dump({
            "last_timestamp": timestamp.strftime(TIMESTAMP_FORMAT)
        }, f)


def parse_log():
    last_timestamp = load_last_timestamp()
    newest_timestamp = last_timestamp

    events = []

    with open(LOG_FILE, "r", errors="ignore") as file:

        for line in file:

            event_type = None

            if "Failed password" in line:
                event_type = "failed"
            elif "Accepted password" in line:
                event_type = "accepted"
            else:
                continue

            time_match = re.match(
                r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})',
                line
            )

            if not time_match:
                continue

            timestamp = datetime.strptime(
                time_match.group(1),
                TIMESTAMP_FORMAT
            )

            # Skip anything we've already sent in a previous run
            if last_timestamp and timestamp <= last_timestamp:
                continue

            ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)

            if not ip_match:
                continue

            ip = ip_match.group(1)

            username = None

            if event_type == "failed":
                user_match = re.search(
                    r'Failed password for (?:invalid user )?(\S+)', line
                )
                if user_match:
                    username = user_match.group(1)

            events.append({
                "ip": ip,
                "username": username,
                "event_type": event_type,
                "timestamp": timestamp.strftime(TIMESTAMP_FORMAT)
            })

            if newest_timestamp is None or timestamp > newest_timestamp:
                newest_timestamp = timestamp

    return events, newest_timestamp


def send_events(events):
    try:
        response = requests.post(WINDOWS_URL, json={"events": events}, timeout=5)
        response.raise_for_status()
        return True

    except requests.exceptions.RequestException as e:
        print(f"Failed to send events to Windows: {e}")
        return False


if __name__ == "__main__":

    events, newest_timestamp = parse_log()

    if not events:
        print("No new SSH events since last check.")

    else:
        print(f"Found {len(events)} new event(s). Sending to Windows...")

        if send_events(events):
            save_last_timestamp(newest_timestamp)
            print("Events sent and state updated.")
        else:
            print("Send failed — state NOT updated, these events will be retried next run.")