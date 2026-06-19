import sqlite3

DB_NAME = "attacks.db"


# ----------------------------
# INIT DATABASE
# ----------------------------
def initialize_database():

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # SSH Events Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ssh_events (

            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            username TEXT,
            event_type TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            received_at DATETIME DEFAULT CURRENT_TIMESTAMP

        )
    """)

    # Alerts Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (

            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            failed_attempts INTEGER NOT NULL,
            usernames_tried INTEGER NOT NULL,
            rapid_attempts INTEGER NOT NULL,
            success_after_failure INTEGER NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP

        )
    """)

    # Blocked IPs Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (

            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL UNIQUE,
            risk_level TEXT NOT NULL,
            blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP

        )
    """)

    conn.commit()
    conn.close()


# ----------------------------
# INSERT SSH EVENT
# ----------------------------
def insert_event(ip, username, event_type, timestamp):

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO ssh_events (
            ip, username, event_type, timestamp
        )
        VALUES (?, ?, ?, ?)
    """, (
        ip,
        username,
        event_type,
        timestamp
    ))

    conn.commit()
    conn.close()


# ----------------------------
# INSERT ALERT
# ----------------------------
def insert_alert(ip, failed_attempts, risk_level):

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO alerts (
            ip,
            failed_attempts,
            risk_level
        )
        VALUES (?, ?, ?)
    """, (
        ip,
        failed_attempts,
        risk_level
    ))

    conn.commit()
    conn.close()


# ----------------------------
# INSERT BLOCKED IP
# ----------------------------
def insert_blocked_ip(ip, risk_level):

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT OR IGNORE INTO blocked_ips (
            ip,
            risk_level
        )
        VALUES (?, ?)
    """, (
        ip,
        risk_level
    ))

    conn.commit()
    conn.close()


# ----------------------------
# DASHBOARD DATA
# ----------------------------
def get_dashboard_data():

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Total events
    cursor.execute("SELECT COUNT(*) FROM ssh_events")
    total_events = cursor.fetchone()[0]

    # Total alerts
    cursor.execute("SELECT COUNT(*) FROM alerts")
    total_alerts = cursor.fetchone()[0]

    # Unique attackers
    cursor.execute("SELECT COUNT(DISTINCT ip) FROM ssh_events")
    unique_attackers = cursor.fetchone()[0]

    # Recent events
    cursor.execute("""
        SELECT *
        FROM ssh_events
        ORDER BY id DESC
        LIMIT 20
    """)
    recent_events = cursor.fetchall()

    # Alerts
    cursor.execute("""
        SELECT *
        FROM alerts
        ORDER BY id DESC
        LIMIT 20
    """)
    alerts = cursor.fetchall()

    # Blocked IPs (FIXED)
    cursor.execute("""
        SELECT ip, risk_level, blocked_at
        FROM blocked_ips
        ORDER BY id DESC
        LIMIT 20
    """)
    blocked_ips = cursor.fetchall()

    conn.close()

    return {
        "total_events": total_events,
        "total_alerts": total_alerts,
        "unique_attackers": unique_attackers,
        "recent_events": recent_events,
        "alerts": alerts,
        "blocked_ips": blocked_ips
    }