#!/usr/bin/env python3
import signal
import threading
import argparse
from scapy.all import sniff, IP, TCP, UDP
import os
import socket
import time
import socketserver
import subprocess
from datetime import datetime

# Globals
active_ips = set()
blocked_ips = set()
scan_detected = False
continuous = False
stop_sniffing = False
attack_history = []

HONEYPOT_PORTS = [2222, 8081]

# TCP scan types
scan_types = {
    'SYN': lambda pkt: pkt[TCP].flags == 0x02,
    'FIN': lambda pkt: pkt[TCP].flags == 0x01,
    'NULL': lambda pkt: pkt[TCP].flags == 0x00,
    'XMAS': lambda pkt: pkt[TCP].flags == 0x29,
    'ACK': lambda pkt: pkt[TCP].flags == 0x10
}

# Handle Ctrl+C
def signal_handler(sig, frame):
    print("\n⛔ Stopped by Ctrl+C")
    global stop_sniffing
    stop_sniffing = True
    exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Send desktop notification
def notify(title, message):
    try:
        subprocess.Popen(['notify-send', '-u', 'normal', '-i', 'dialog-warning', title, message])
    except Exception as e:
        print(f"❌ Notification failed: {e}")

# Block attacker IP
def block_ip(ip):
    if ip in blocked_ips:
        print(f"⚠️  {ip} already blocked.")
        return
    os.system(f"iptables -A INPUT -s {ip} -j DROP")
    blocked_ips.add(ip)
    print(f"🚫 Blocked IP: {ip}")
    notify("DogPro Blocked IP", f"{ip} has been blocked")

# Unblock an IP
def unblock_ip(ip):
    print(f"🔓 Attempting to unblock {ip}...")
    result = os.system(f"iptables -D INPUT -s {ip} -j DROP")
    if result == 0:
        blocked_ips.discard(ip)
        print(f"✅ Unblocked IP: {ip}")
    else:
        print(f"⚠️  Could not unblock {ip}. Rule may not exist.")

# Reverse DNS lookup
def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "unknown"

# Log scan event
def alert(pkt, scan_type):
    global scan_detected
    src_ip = pkt[IP].src
    dst_port = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport
    hostname = get_hostname(src_ip)
    print(f"\n🔍 {scan_type} scan from {src_ip} ({hostname}) on port {dst_port}")
    notify("DogPro Alert", f"{scan_type} scan from {src_ip} on port {dst_port}")
    scan_detected = True
    active_ips.add(src_ip)

    # Add to history
    attack_history.append({
        'time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'type': scan_type,
        'ip': src_ip,
        'port': dst_port
    })

# Analyze packets
def process_packet(pkt):
    if IP in pkt:
        if TCP in pkt:
            for scan, check in scan_types.items():
                if check(pkt):
                    alert(pkt, scan)
                    break
        elif UDP in pkt:
            alert(pkt, "UDP")

# Sniff packets once
def sniff_once(timeout=10):
    global stop_sniffing, scan_detected, active_ips
    stop_sniffing = False
    scan_detected = False
    active_ips.clear()
    print(f"\n⏳ Scanning network for {timeout} seconds...")
    sniff(prn=process_packet, timeout=timeout)

# Keyboard input listener
def key_listener():
    global stop_sniffing
    while True:
        cmd = input().strip().lower()
        if cmd == 'q':
            print("👋 Quitting.")
            stop_sniffing = True
            os._exit(0)
        elif cmd == 's' and scan_detected:
            for ip in active_ips:
                block_ip(ip)
        elif cmd == 'h':
            print("\n📜 Attack History:")
            if not attack_history:
                print("No attacks recorded.")
            else:
                for event in attack_history:
                    print(f"[{event['time']}] {event['type']} from {event['ip']} on port {event['port']}")

# Honeypot trap
class HoneypotHandler(socketserver.BaseRequestHandler):
    def handle(self):
        attacker_ip = self.client_address[0]
        port = self.server.server_address[1]
        print(f"\n🧪 Honeypot triggered by: {attacker_ip}")
        notify("DogPro Honeypot Triggered", f"Connection from {attacker_ip}")
        if attacker_ip not in blocked_ips and not attacker_ip.startswith("127."):
            block_ip(attacker_ip)
        try:
            self.request.sendall(b"SSH-2.0-OpenSSH_7.4\r\n")
        except:
            pass
        attack_history.append({
            'time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'type': "Honeypot",
            'ip': attacker_ip,
            'port': port
        })

# Start honeypots
def start_honeypots():
    servers = []
    for port in HONEYPOT_PORTS:
        try:
            server = socketserver.ThreadingTCPServer(("0.0.0.0", port), HoneypotHandler)
            server.daemon_threads = True
            t = threading.Thread(target=server.serve_forever)
            t.daemon = True
            t.start()
            servers.append(server)
            print(f"🪤 Honeypot active on port {port}")
        except Exception as e:
            print(f"❌ Failed to bind honeypot on port {port}: {e}")
    return servers

# Main logic
def main():
    global continuous
    parser = argparse.ArgumentParser(description="DogPro Defender with Desktop Alerts")
    parser.add_argument("-i", action="store_true", help="Continuous mode")
    parser.add_argument("-u", metavar="IP", help="Unblock an IP address and exit")
    args = parser.parse_args()

    # Unblock mode
    if args.u:
        unblock_ip(args.u)
        exit(0)

    # Require root
    if os.geteuid() != 0:
        print("❌ You must run this tool as root (sudo) for blocking to work.")
        exit(1)

    continuous = args.i

    # Start honeypots
    start_honeypots()

    # Listen for key commands
    threading.Thread(target=key_listener, daemon=True).start()

    if continuous:
        print("🔁 Continuous mode: Scanning every 10 seconds")
        while True:
            sniff_once(timeout=10)
            if not scan_detected:
                print("✅ Clear network.")
            time.sleep(10)
    else:
        sniff_once(timeout=10)
        if not scan_detected:
            print("✅ Clear network.")

if __name__ == "__main__":
    main()
