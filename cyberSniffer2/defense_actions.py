import subprocess
import time
from datetime import datetime
import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))

WHITELIST_FILE = os.path.join(BASE_DIR, "whitelist.txt")
LOG_FILE = os.path.join(BASE_DIR, "security_log.txt")

ALERT_COOLDOWN_SECONDS = 10
_last_alert_time = {}


def load_whitelist():
    if not os.path.exists(WHITELIST_FILE):
        return set()

    try:
        with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
            return set(line.strip() for line in f if line.strip())
    except Exception:
        return set()


def log_alert(ip, mac, proto, port, reason):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = (
        f"[{timestamp}] ALERT: {reason} | "
        f"Attacker IP: {ip} | Attacker MAC: {mac} | Proto: {proto}/{port}\n"
    )

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(entry)


def get_rule_name(ip):
    return f"BLOCK_CYBER_{ip.replace('.', '_').replace(':', '_')}"


def is_ip_blocked(ip):
    rule_name = get_rule_name(ip)

    try:
        cmd = f'netsh advfirewall firewall show rule name="{rule_name}"'
        output = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)
        return "No rules match" not in output
    except Exception:
        return False


def block_ip(ip):
    whitelist = load_whitelist()

    if ip in whitelist:
        print(f"[WHITELIST] Skipping block for {ip}")
        return

    if is_ip_blocked(ip):
        return

    rule_name = get_rule_name(ip)

    cmd_in = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}",
        "dir=in",
        "action=block",
        f"remoteip={ip}",
        "enable=yes"
    ]

    cmd_out = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}",
        "dir=out",
        "action=block",
        f"remoteip={ip}",
        "enable=yes"
    ]

    subprocess.run(cmd_in, capture_output=True, text=True, shell=True)
    subprocess.run(cmd_out, capture_output=True, text=True, shell=True)

    print(f"[BLOCKED] {ip} blocked inbound + outbound")


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
