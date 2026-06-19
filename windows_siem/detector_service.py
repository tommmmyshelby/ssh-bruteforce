from datetime import datetime
import sqlite3
import requests
import os

from database import insert_blocked_ip

DB_NAME = "attacks.db"
UBUNTU_BLOCK_URL = "http://192.168.56.103:5001/block"


# ----------------------------
# BLOCK REQUEST FUNCTION
# ----------------------------
def block_ip(ip):
    try:
        print(f"[BLOCK DEBUG] Sending request → {ip}")

        response = requests.post(
            UBUNTU_BLOCK_URL,
            json={"ip": ip},
            timeout=5
        )

        print(f"[BLOCK RESPONSE STATUS] {response.status_code}")
        print(f"[BLOCK RESPONSE TEXT] {response.text}")

    except Exception as e:
        print(f"[BLOCK ERROR] {e}")


# ----------------------------
# DETECTOR ENGINE
# ----------------------------
def calculate_risk():

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT ip, username, event_type, timestamp
        FROM ssh_events
        ORDER BY timestamp
    """)

    rows = cursor.fetchall()

    attack_data = {}

    # ----------------------------
    # BUILD ATTACK PROFILE
    # ----------------------------
    for ip, username, event_type, timestamp in rows:

        if ip not in attack_data:
            attack_data[ip] = {
                "attempts": 0,
                "usernames": set(),
                "timestamps": [],
                "success": False
            }

        if event_type == "failed":
            attack_data[ip]["attempts"] += 1

            if username:
                attack_data[ip]["usernames"].add(username)

            try:
                attack_data[ip]["timestamps"].append(
                    datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S")
                )
            except Exception:
                pass

        elif event_type == "accepted":
            attack_data[ip]["success"] = True

    # ----------------------------
    # ANALYZE RISK
    # ----------------------------
    for ip, data in attack_data.items():

        attempts = data["attempts"]
        usernames = len(data["usernames"])
        timestamps = sorted(data["timestamps"])
        success = data["success"]

        score = 0

        if attempts >= 5:
            score += 2
        if attempts >= 10:
            score += 3
        if attempts >= 20:
            score += 5

        if usernames >= 3:
            score += 4

        rapid_attempts = 0
        for i in range(1, len(timestamps)):
            diff = (timestamps[i] - timestamps[i - 1]).total_seconds()
            if diff <= 1:
                rapid_attempts += 1

        if rapid_attempts >= 5:
            score += 5

        if success:
            score += 6

        # ----------------------------
        # RISK LEVEL
        # ----------------------------
        if score >= 12:
            risk = "HIGH"
        elif score >= 6:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        print(f"[DEBUG] IP={ip} SCORE={score} RISK={risk}")

        if risk == "LOW":
            continue

        # ----------------------------
        # INSERT ALERT (NO SKIP LOGIC BUG ANYMORE)
        # ----------------------------
        cursor.execute("""
            SELECT COUNT(*) FROM alerts WHERE ip = ?
        """, (ip,))
        exists = cursor.fetchone()[0]

        if exists == 0:
            cursor.execute("""
                INSERT INTO alerts (
                    ip,
                    failed_attempts,
                    usernames_tried,
                    rapid_attempts,
                    success_after_failure,
                    risk_score,
                    risk_level
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                ip,
                attempts,
                usernames,
                rapid_attempts,
                int(success),
                score,
                risk
            ))

            print(f"[ALERT] {ip} Score={score} Risk={risk}")
        else:
            print(f"[INFO] Alert exists for {ip} (still allowing block execution)")

        # ----------------------------
        # BLOCK ONLY HIGH RISK
        # ----------------------------
        if risk.strip().upper() == "HIGH":

            print(f"[BLOCKING] {ip}")

            # UFW block rule (top priority)
            os.system(f"sudo ufw insert 1 deny from {ip} to any port 22 proto tcp")

            # Save to DB
            insert_blocked_ip(ip, risk)

            # Send block request (IMPORTANT FIX)
            block_ip(ip)

            print(f"[BLOCKED SUCCESSFULLY] {ip}")


    conn.commit()
    conn.close()


# ----------------------------
# RUN MANUALLY
# ----------------------------
if __name__ == "__main__":
    calculate_risk()