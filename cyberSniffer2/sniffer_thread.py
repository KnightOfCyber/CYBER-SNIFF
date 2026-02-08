import time
from datetime import datetime
from collections import defaultdict, deque

from PyQt5.QtCore import QThread, QObject, pyqtSignal
from scapy.all import AsyncSniffer, IP, IPv6, TCP, UDP, Ether

from defense_actions import is_ip_blocked


class SnifferSignal(QObject):
    packet_data = pyqtSignal(list)
    alert_signal = pyqtSignal(str, str, str, str, str)


class SnifferThread(QThread):
    def __init__(self, iface, bpf_filter=None, api_key=None):
        super().__init__()
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.api_key = api_key

        self.packet_data = None
        self.alert_signal = None

        self.sniffer = None
        self.running = True

        # Tracking
        self.ip_packet_times = defaultdict(lambda: deque(maxlen=5000))
        self.ip_ports_seen = defaultdict(lambda: deque(maxlen=500))
        self.ip_critical_hits = defaultdict(lambda: deque(maxlen=1000))

        # Critical ports
        self.critical_ports = {21, 22, 23, 135, 139, 445, 3389, 5900, 5985, 5986}

        # Whitelist (router + localhost + your PC)
        self.whitelist = {
            "127.0.0.1",
            "::1",
            "192.168.1.1",   # router
            "192.168.1.7"    # your PC
        }

    def stop(self):
        self.running = False
        if self.sniffer:
            try:
                self.sniffer.stop()
            except Exception:
                pass

    def run(self):
        try:
            self.sniffer = AsyncSniffer(
                iface=self.iface,
                filter=self.bpf_filter,
                prn=self.process_packet,
                store=False
            )
            self.sniffer.start()

            while self.running:
                time.sleep(0.2)

            if self.sniffer:
                self.sniffer.stop()

        except Exception as e:
            # DO NOT TRIGGER SECURITY ALERT ON ERROR/STOP
            print("Sniffer Error:", e)

    def is_local_ip(self, ip):
        return ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16.")

    def classify_severity(self, sport, dport, src_ip):
        now = time.time()

        # Whitelist ignore
        if src_ip in self.whitelist:
            return "NORMAL", "Whitelisted Device"

        # If already blocked, don't treat it as CRITICAL again
        if is_ip_blocked(src_ip):
            return "BLOCKED", "Attacker IP already blocked"

        ports = []
        if sport.isdigit():
            ports.append(int(sport))
        if dport.isdigit():
            ports.append(int(dport))

        # FTP/Telnet always critical
        if 21 in ports or 23 in ports:
            return "CRITICAL", "Unencrypted Login Port (FTP/Telnet)"

        # Port scan detection
        if dport.isdigit():
            dp = int(dport)
            self.ip_ports_seen[src_ip].append((dp, now))

            recent_ports = [p for p, t in self.ip_ports_seen[src_ip] if now - t <= 10]
            unique_ports = len(set(recent_ports))

            if unique_ports >= 12:
                return "CRITICAL", "Port Scan Detected (12+ ports in 10 sec)"
            elif unique_ports >= 7:
                return "WARNING", "Suspicious Port Scan Activity"

        # Brute force detection on critical ports
        for p in ports:
            if p in self.critical_ports:
                self.ip_critical_hits[src_ip].append(now)
                recent_hits = [t for t in self.ip_critical_hits[src_ip] if now - t <= 8]

                if len(recent_hits) >= 25:
                    return "CRITICAL", f"Brute Force Attack Suspected on Port {p}"
                elif len(recent_hits) >= 12:
                    return "WARNING", f"High Access Attempts on Port {p}"

        # Flood detection for 80/443 ONLY for non-local IPs
        if (80 in ports or 443 in ports) and not self.is_local_ip(src_ip):
            self.ip_packet_times[src_ip].append(now)
            recent = [t for t in self.ip_packet_times[src_ip] if now - t <= 3]

            if len(recent) > 700:
                return "CRITICAL", "Possible Web Flood Attack (80/443)"
            elif len(recent) > 300:
                return "WARNING", "High Web Traffic Spike (80/443)"

        return "NORMAL", "Normal Traffic"

    def process_packet(self, pkt):
        try:
            timestamp = datetime.now().strftime("%H:%M:%S")

            src_ip = "-"
            dst_ip = "-"
            proto = "Other"
            sport = "N/A"
            dport = "N/A"
            length = str(len(pkt))
            summary = pkt.summary()

            src_mac = "N/A"
            if Ether in pkt:
                src_mac = pkt[Ether].src

            # IPv4 / IPv6
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                proto = "IPv4"

            elif IPv6 in pkt:
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst
                proto = "IPv6"

            # TCP / UDP
            if TCP in pkt:
                proto = "TCP"
                sport = str(pkt[TCP].sport)
                dport = str(pkt[TCP].dport)

            elif UDP in pkt:
                proto = "UDP"
                sport = str(pkt[UDP].sport)
                dport = str(pkt[UDP].dport)

            severity, reason = self.classify_severity(sport, dport, src_ip)

            if severity == "CRITICAL":
                severity_label = "🚨 CRITICAL"
            elif severity == "WARNING":
                severity_label = "⚠ WARNING"
            elif severity == "BLOCKED":
                severity_label = "🛑 BLOCKED"
            else:
                severity_label = "NORMAL"

            row = [
                timestamp,
                src_ip,
                dst_ip,
                proto,
                sport,
                dport,
                length,
                severity_label,
                summary
            ]

            if self.packet_data:
                self.packet_data.emit(row)

            # Only trigger alert ONCE when critical
            if severity == "CRITICAL" and self.alert_signal:
                # If already blocked, skip popup/alert
                if not is_ip_blocked(src_ip):
                    self.alert_signal.emit(
                        src_ip,
                        src_mac,
                        proto,
                        dport,
                        reason
                    )

        except Exception:
            pass
