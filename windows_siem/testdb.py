import sqlite3

conn = sqlite3.connect("attacks.db")
cursor = conn.cursor()

# Show all SSH events
cursor.execute("""
    SELECT *
    FROM ssh_events
    ORDER BY id DESC
""")

print("\n=== SSH EVENTS ===")
for row in cursor.fetchall():
    print(row)

# Show alerts
cursor.execute("""
    SELECT *
    FROM alerts
    ORDER BY id DESC
""")

print("\n=== ALERTS ===")
for row in cursor.fetchall():
    print(row)

# Show blocked IPs
cursor.execute("""
    SELECT *
    FROM blocked_ips
    ORDER BY id DESC
""")

print("\n=== BLOCKED IPS ===")
for row in cursor.fetchall():
    print(row)

conn.close()