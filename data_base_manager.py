import sqlite3
from datetime import datetime

DB_NAME = "ids_database.db"
TARGET = "68.220.171.94"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    conn.execute('''CREATE TABLE IF NOT EXISTS security_events
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp DATETIME,
                  attacker_ip TEXT, target_ip TEXT, port_number INTEGER,
                  attack_type TEXT, severity TEXT, attack_count INTEGER)''')
    conn.close()

def log_attack(attacker_ip, attack_type, severity, port, count):
    """Saves attack data—No changes here to prevent errors in detection."""
    try:
        conn = sqlite3.connect(DB_NAME)
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        conn.execute('''INSERT INTO security_events 
                       (timestamp, attacker_ip, target_ip, port_number, attack_type, severity, attack_count)
                       VALUES (?, ?, ?, ?, ?, ?, ?)''', 
                       (now, attacker_ip, TARGET, port, attack_type, severity, count))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"DB Error: {e}")

def get_report_data():
    """Fetches the last 20 attacks for the professional report."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, attacker_ip, target_ip, port_number, attack_type, severity FROM security_events ORDER BY id DESC LIMIT 20")
    rows = cursor.fetchall()
    conn.close()
    return rows

init_db()
