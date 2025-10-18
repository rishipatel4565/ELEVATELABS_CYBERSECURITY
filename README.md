# 🔥 Personal Firewall using Python

### 📘 Abstract
A personal firewall monitors and controls incoming and outgoing network traffic. 
This Python-based firewall filters packets, applies user-defined rules, and logs suspicious activities. 
It uses **Scapy** for packet sniffing, **iptables** for enforcing rules, and **Tkinter** for live monitoring.

---

### 🛠️ Tools Used
- Python 3
- Scapy
- Tkinter
- iptables (Linux)
- Logging Module

---

### ⚙️ Installation
```bash
git clone https://github.com/<your-username>/personal-firewall-python.git
cd personal-firewall-python
pip install -r requirements.txt
```

### 🚀 Run the Firewall
```bash
sudo python3 personal_firewall.py
```
Options:
- `--iface eth0` → specify interface
- `--nogui` → disable GUI

---

### 📄 Rules Format
```json
[
  {"name": "block_ssh", "action": "block", "protocol": "TCP", "dst_port": 22},
  {"name": "alert_dns", "action": "alert", "protocol": "UDP", "dst_port": 53}
]
```

---

### 🧩 Steps Involved
1. Installed Scapy and Tkinter
2. Designed JSON-based rule engine
3. Implemented packet capture
4. Applied rule matching logic
5. Integrated iptables for blocking
6. Added logging and GUI for live view

---

### 🧭 Conclusion
This project demonstrates how Python can be used to build a customizable personal firewall. 
It provides insight into network traffic control and cybersecurity fundamentals.

**Author:** Rishi Patel  
**Domain:** Cybersecurity and Digital Forensics
