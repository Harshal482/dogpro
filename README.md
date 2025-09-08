# DogPro Defender 🐶🛡️

**DogPro Defender** is a lightweight, offline-capable personal network defense tool for Linux.  
It detects network attacks, scans, and suspicious connections, automatically blocks malicious IPs, and runs honeypot traps to lure attackers.  

---

## ⚡ Features

- **Network scan detection**  
  Detects TCP scans: SYN, FIN, NULL, XMAS, ACK, and UDP scans.  
- **Automatic blocking**  
  Blocks attacker IPs using `iptables`.  
- **Honeypot traps**  
  Simulates SSH and HTTP services to trap attackers on ports `2222` and `8081`.  
- **Desktop notifications**  
  Alerts via `notify-send` (Linux desktop environments).  
- **Attack history**  
  Logs attack type, IP, port, and timestamp.  
- **Interactive commands**
  - `-i`→ continuos mode (if you start with -i it'll scan continuos for every 10 sec )  
  - `q` → Quit  
  - `s` → Block detected IPs  
  - `h` → Show attack history 
  - `c` → ctrl+c to stop the scan 

---
Required modules
sudo apt update
pip install scapy
sudo apt install libnotify-bin

## 🖥️ Requirements

- **Linux** (Debian/Ubuntu recommended)  
- **Python 3**  
- **Scapy library**:

```bash
pip install scapy
