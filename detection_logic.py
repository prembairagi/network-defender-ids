from database_manager import log_attack
from datetime import datetime

# Stateful tracking for thresholds
state = {"icmp": {}, "ports": {}}
TARGET_IP = "68.220.171.94"

def analyze_traffic(data):
    if not data: return
    src = data["src_ip"]
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Rule 1: ICMP Flood (Threshold: 50)
    if data.get("type") == "ICMP" and data.get("icmp_type") == 8:
        state["icmp"][src] = state["icmp"].get(src, 0) + 1
        if state["icmp"][src] > 50:
            log_attack(src, "ICMP Flood", "High", 0, state["icmp"][src])
            # Formatted terminal print
            print(f"{now:<20} | {src:<15} | {TARGET_IP:<15} | {'0':<6} | {'ICMP Flood':<15} | {'High':<8}")
            state["icmp"][src] = 0

    # Rule 2: Port Scan (Threshold: 10 unique ports)
    if data.get("type") == "TCP":
        port = data["dst_port"]
        if src not in state["ports"]: state["ports"][src] = set()
        state["ports"][src].add(port)
        if len(state["ports"][src]) > 10:
            log_attack(src, "Port Scan", "Medium", port, len(state["ports"][src]))
            # Formatted terminal print
            print(f"{now:<20} | {src:<15} | {TARGET_IP:<15} | {port:<6} | {'Port Scan':<15} | {'Medium':<8}")
            state["ports"][src] = set()
 