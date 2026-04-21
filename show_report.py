import os
from database_manager import get_report_data

def generate_grid_report():
    rows = get_report_data()
    
    # Grid Design Elements
    border = "+---------------------+-----------------+-----------------+--------+-----------------+----------+"
    header = "|      TIMESTAMP      |   ATTACKER IP   |    TARGET IP    |  PORT  |   ATTACK TYPE   | SEVERITY |"
    
    os.system('clear')
    print("\n" + "="*96)
    print(f"{'FINAL DATABASE SECURITY REPORT - LAST 20 EVENTS':^96}")
    print("="*96)
    print(border)
    print(header)
    print(border)

    if not rows:
        print(f"| {'NO ATTACKS DETECTED YET':^94} |")
    else:
        for r in rows:
            # Formatting each column to match the grid design
            print(f"| {r[0]:<19} | {r[1]:<15} | {r[2]:<15} | {r[3]:<6} | {r[4]:<15} | {r[5]:<8} |")
    
    print(border)
    print(f"Report Generated: {rows[0][0] if rows else 'N/A'}\n")

if __name__ == "__main__":
    generate_grid_report()
