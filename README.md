
# CYBER-SNIFF
### Advanced Network Security Monitoring and Auto-Blocking Tool

CYBER-SNIFF is a **real-time network monitoring and intrusion detection tool** built using Python.
The tool captures live network packets, analyzes traffic behavior, detects suspicious activity such as port scanning
and brute-force attempts, and automatically blocks malicious IP addresses using Windows Firewall.

This project was developed as a **Cyber Security Mini Project** to demonstrate packet sniffing and automated network defense techniques.

---

# Features

- Real-time packet monitoring
- Suspicious activity detection
- Automatic IP blocking using Windows Firewall
- Whitelist management for trusted devices
- Security event logging
- Graphical monitoring dashboard
- Background system tray operation
- Severity classification (Normal / Warning / Critical)

---

# Technologies Used

| Technology | Purpose |
|------------|--------|
| Python | Core programming language |
| Scapy | Packet sniffing and network analysis |
| PyQt5 | Graphical User Interface |
| Windows Firewall | Automatic IP blocking |
| Nmap | Testing and attack simulation |

---

# Project Structure

```
CYBER-SNIFF
│
├── main_sniffer.py
├── sniffer_thread.py
├── defense_actions.py
├── whitelist.txt
├── security_log.txt
├── icons/
│
└── README.md
```

---

# How CYBER-SNIFF Works

1. The tool captures live packets from the selected network interface.
2. Traffic data is analyzed for suspicious patterns.
3. The detection engine identifies activities such as:
   - Port scanning
   - Brute force attempts
   - Abnormal traffic spikes
4. If a critical threat is detected:
   - The attacker IP is blocked automatically using Windows Firewall.
5. The event is logged in **security_log.txt**.

---

# Requirements

Python 3.9 or later

Required libraries:

```
pip install scapy
pip install pyqt5
pip install psutil
```

---

# How to Run the Project (VS Code)

### Step 1 – Clone the Repository

```
git clone https://github.com/KnightOfCyber/CYBER-SNIFF.git
```

### Step 2 – Open in VS Code

Open the project folder in **Visual Studio Code**.

### Step 3 – Install Dependencies

```
pip install scapy pyqt5 psutil
```

### Step 4 – Run the Application

```
python main_sniffer.py
```

The CYBER-SNIFF interface will start.

---

# Whitelist Feature

Trusted IP addresses can be added to the whitelist to prevent blocking.

Whitelist file:

```
whitelist.txt
```

Example:

```
192.168.1.10
192.168.1.5
```

---

# Security Logs

All detected threats are recorded in:

```
security_log.txt
```

Example log entry:

```
[2025-04-10 12:14:22]
ALERT: Port Scan Detected
Attacker IP: 192.168.1.45
Protocol: TCP/445
Action: BLOCKED
```

---

# Testing the Tool

You can simulate attacks using **Nmap**.

```
nmap -sS 192.168.1.5
```

The tool will detect scanning behavior and block the attacker.

---

# Advantages

- Real-time detection
- Automatic response to threats
- Lightweight and easy to use
- Useful for educational cybersecurity labs

---

# Limitations

- Currently optimized for Windows environments
- Detection is rule-based (not machine learning)

---

# Future Improvements

Possible improvements include:

- Machine learning based threat detection
- Geo-IP attacker tracking
- Distributed network monitoring
- Web dashboard monitoring

---

# Author

Developed as a **Cyber Security Mini Project**

Students:
- P. Pavan Durga Satish
- Team Members
- T.Venkatesh
- G.Pavani
- D.Pujitha
- Y.Karthik

---

# License

This project is developed for **educational purposes**.
