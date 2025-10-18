#!/usr/bin/env python3
# personal_firewall.py
import json
import os
import time
import logging
import subprocess
import threading
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP
try:
    import tkinter as tk
    from tkinter.scrolledtext import ScrolledText
    GUI_AVAILABLE = True
except Exception:
    GUI_AVAILABLE = False

RULES_FILE = "rules.json"
LOG_FILE = "firewall.log"

logger = logging.getLogger("PersonalFirewall")
logger.setLevel(logging.INFO)
fh = logging.FileHandler(LOG_FILE)
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)

def load_rules():
    if not os.path.exists(RULES_FILE):
        with open(RULES_FILE, "w") as f:
            json.dump([], f, indent=2)
    with open(RULES_FILE) as f:
        return json.load(f)

def match_rule(pkt, rule):
    if not IP in pkt:
        return False
    ip = pkt[IP]
    proto = None
    src_port = None
    dst_port = None
    if TCP in pkt:
        proto = "TCP"
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
    elif UDP in pkt:
        proto = "UDP"
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
    else:
        proto = "ANY"

    if rule.get("protocol") and rule["protocol"] != "ANY":
        if rule["protocol"] != proto:
            return False
    if rule.get("src_ip") and rule["src_ip"] != ip.src:
        return False
    if rule.get("dst_ip") and rule["dst_ip"] != ip.dst:
        return False
    if rule.get("src_port") and int(rule["src_port"]) != (src_port or -1):
        return False
    if rule.get("dst_port") and int(rule["dst_port"]) != (dst_port or -1):
        return False
    return True

def add_iptables_drop(ip):
    cmd = ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"]
    try:
        subprocess.run(cmd, check=True)
        logger.info(f"iptables DROP added for {ip}")
        return True
    except Exception as e:
        logger.error(f"Failed to add iptables rule: {e}")
        return False

def handle_match(pkt, rule, gui_queue=None):
    ip = pkt[IP]
    action = rule.get("action", "alert")
    entry = {
        "time": datetime.utcnow().isoformat()+"Z",
        "rule": rule.get("name"),
        "action": action,
        "src": ip.src,
        "dst": ip.dst,
        "proto": rule.get("protocol") or ("TCP" if TCP in pkt else "UDP" if UDP in pkt else "OTHER")
    }
    logger.info(f"Matched rule: {entry}")
    if gui_queue is not None:
        gui_queue.append(entry)
    if action == "block":
        add_iptables_drop(ip.src)
    return entry

stop_sniff = False
def packet_callback(pkt):
    rules = load_rules()
    for rule in rules:
        try:
            if match_rule(pkt, rule):
                handle_match(pkt, rule, gui_queue=packet_callback.gui_queue)
                if rule.get("action") == "block":
                    break
        except Exception as e:
            logger.exception(f"Error matching rule {rule.get('name')}: {e}")

def start_sniff(interface=None):
    packet_callback.gui_queue = []
    logger.info("Starting sniffing...")
    sniff(prn=packet_callback, store=0, iface=interface)

def start_gui_loop():
    if not GUI_AVAILABLE:
        print("Tkinter not available; GUI disabled.")
        return
    root = tk.Tk()
    root.title("Personal Firewall Monitor")
    root.geometry("700x400")
    st = ScrolledText(root, state="disabled", wrap="word")
    st.pack(fill="both", expand=True)

    def refresh():
        q = packet_callback.gui_queue
        while q:
            entry = q.pop(0)
            line = f"{entry['time']} | {entry['action']} | {entry['rule']} | {entry['src']} -> {entry['dst']} | {entry['proto']}\n"
            st.configure(state="normal")
            st.insert("end", line)
            st.see("end")
            st.configure(state="disabled")
        root.after(1000, refresh)
    root.after(1000, refresh)
    root.mainloop()

def ensure_demo_rules():
    if os.path.exists(RULES_FILE):
        return
    demo = [
      {"name":"block_example_ssh","action":"block","src_ip":"192.0.2.5","protocol":"TCP","dst_port":22},
      {"name":"alert_udp_53","action":"alert","protocol":"UDP","dst_port":53}
    ]
    with open(RULES_FILE,"w") as f:
        json.dump(demo,f,indent=2)
    logger.info("Demo rules created.")

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--iface", help="Interface to sniff on", default=None)
    p.add_argument("--nogui", action="store_true", help="Disable GUI")
    args = p.parse_args()

    ensure_demo_rules()

    sniffer_thread = threading.Thread(target=start_sniff, args=(args.iface,), daemon=True)
    sniffer_thread.start()

    if not args.nogui and GUI_AVAILABLE:
        start_gui_loop()
    else:
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("Stopping...")
            logger.info("User stopped firewall.")
