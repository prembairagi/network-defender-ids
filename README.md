# Network Defender IDS

A Python-based Hybrid Intrusion Detection System (HIDS/NIDS) that monitors live network traffic, detects attacks in real time, and logs incidents to a SQLite database.

## Features
- Real-time packet sniffing via Scapy
- Detects ICMP Flood and Port Scan attacks
- Threshold-based stateful detection engine
- SQLite logging for persistent attack records
- Live terminal dashboard with formatted output

## Tech Stack
Python · Scapy · SQLite · Linux (eth0)

## Project Structure
| File | Role |
|---|---|
| `core_ids.py` | Entry point, packet capture loop |
| `detection_logic.py` | Attack detection rules & thresholds |
| `data_decoder.py` | Raw packet decoding |
| `database_manager.py` | SQLite logging |
| `show_report.py` | Report display |

## How to Run
```bash
pip install scapy
sudo python3 core_ids.py