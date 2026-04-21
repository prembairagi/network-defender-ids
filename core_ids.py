import os
from scapy.all import sniff
from data_decoder import decode_packet
from detection_logic import analyze_traffic

# Standardized Column Configuration
HEADER = f"{'TIMESTAMP':<20} | {'ATTACKER IP':<15} | {'TARGET IP':<15} | {'PORT':<6} | {'ATTACK TYPE':<15} | {'SEVERITY':<8}"
LINE = "-" * len(HEADER)

def ids_main_callback(packet):
    decoded_data = decode_packet(packet)
    if decoded_data:
        analyze_traffic(decoded_data)

def display_dashboard():
    # Clears terminal for a professional look
    os.system('clear')
    print(LINE)
    print(f"{'NETWORK DEFENDER IDS - LIVE MONITORING':^105}")
    print(LINE)
    print(HEADER)
    print(LINE)
    print(f"🚀 STATUS: ACTIVE | TARGET SERVER: 68.220.171.94 | SHOWING LAST 20 ALERTS")
    print(LINE + "\n")

if __name__ == "__main__":
    display_dashboard()
    try:
        sniff(iface="eth0", prn=ids_main_callback, store=0)
    except KeyboardInterrupt:
        print(f"\n{LINE}\n[!] System Shutdown. Log saved to ids_database.db\n{LINE}")
