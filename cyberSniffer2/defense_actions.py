import subprocess
import time
from datetime import datetime

LOG_FILE = "security_log.txt"

# Cooldown system (prevents popup spam / crashing)
ALERT_COOLDOWN_SECONDS = 10
_last_alert_time = {}


def can_show_alert(attacker_ip):
    """Return True if alert popup can be shown (cooldown based)."""
    now = time.time()
    last = _last_alert_time.get(attacker_ip, 0)

    if now - last >= ALERT_COOLDOWN_SECONDS:
        _last_alert_time[attacker_ip] = now
        return True

    return False


def log_alert(ip, mac, proto, port, reason):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = (
        f"[{timestamp}] ALERT: {reason} | "
        f"Attacker IP: {ip} | Attacker MAC: {mac} | Proto: {proto}/{port}\n"
    )

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(entry)


def is_ip_blocked(ip):
    """Check if IP is already blocked in Windows Firewall."""
    try:
        cmd = f'netsh advfirewall firewall show rule name=all | findstr "{ip}"'
        output = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)
        return ip in output
    except:
        return False


def block_ip(ip):
    # Ignore invalid / local system IPs
    if ip in ["0.0.0.0", "-", "127.0.0.1", "::1"]:
        return

    if is_ip_blocked(ip):
        return

    rule_name = f"BLOCK_CYBER_{ip.replace('.', '_').replace(':', '_')}"

    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}",
        "dir=in",
        "action=block",
        f"remoteip={ip}",
        "enable=yes"
    ]

    subprocess.run(cmd, capture_output=True, text=True, shell=True)


def reset_network_settings(action):
    if action == "flushdns":
        cmd = ["ipconfig", "/flushdns"]
        msg = "DNS cache flushed successfully."
    elif action == "renew":
        cmd = ["ipconfig", "/renew"]
        msg = "IP address renewed successfully."
    else:
        return "Invalid action"

    subprocess.run(cmd, capture_output=True, text=True, shell=True)
    return msg
