import os
import sys
import time
def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        base_path = sys._MEIPASS   # PyInstaller temp folder
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QTableWidget, QTableWidgetItem, QPushButton,
    QLabel, QComboBox, QMessageBox, QLineEdit
)
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import QSize, Qt
from PyQt5 import QtGui

from scapy.arch.windows import get_windows_if_list

from sniffer_thread import SnifferThread, SnifferSignal
from defense_actions import log_alert, block_ip, reset_network_settings

API_KEY = os.getenv("ABUSEIPDB_API_KEY")


class CyberSniffer(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("CYBER-SNIFF | Advanced Security and Diagnostics Suite")
        self.setWindowIcon(QIcon(resource_path("app_icon.ico")))
        self.setGeometry(120, 120, 1500, 780)

        self.signal = SnifferSignal()
        self.signal.packet_data.connect(self.add_row)
        self.signal.alert_signal.connect(self.handle_alert)

        self.sniffer = None

        # Anti-popup spam protection
        self.alerted_ips = set()
        self.last_alert_time = {}
        self.alert_cooldown = 20  # seconds

        self.build_ui()
        self.apply_style()

    def build_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(8)

        # ---------------------------
        # TOP BAR
        # ---------------------------
        top_bar = QHBoxLayout()

        self.interface_label = QLabel("Interface:")
        self.interface_label.setFixedWidth(70)

        self.interface_box = QComboBox()
        self.interface_box.setFixedWidth(420)

        interfaces = get_windows_if_list()
        if interfaces:
            self.interface_box.addItems([i["name"] for i in interfaces])
        else:
            self.interface_box.addItem("No interfaces found")

        self.filter_label = QLabel("BPF Filter:")
        self.filter_label.setFixedWidth(70)

        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("e.g. tcp port 80 or host 192.168.1.1")
        self.filter_input.setFixedHeight(32)

        self.start_btn = QPushButton()
        self.start_btn.setIcon(QIcon(resource_path("icons/play.png")))
        self.start_btn.setIconSize(QSize(28, 28))
        self.start_btn.setFixedSize(52, 42)
        self.start_btn.clicked.connect(self.start_sniffing)

        self.stop_btn = QPushButton()
        self.stop_btn.setIcon(QIcon(resource_path("icons/stop.png")))
        self.stop_btn.setIconSize(QSize(28, 28))
        self.stop_btn.setFixedSize(52, 42)
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_sniffing)

        self.clear_btn = QPushButton()
        self.clear_btn.setIcon(QIcon(resource_path("icons/clear.png")))
        self.clear_btn.setIconSize(QSize(28, 28))
        self.clear_btn.setFixedSize(52, 42)
        self.clear_btn.clicked.connect(self.clear_table)

        top_bar.addWidget(self.interface_label)
        top_bar.addWidget(self.interface_box)
        top_bar.addSpacing(10)
        top_bar.addWidget(self.filter_label)
        top_bar.addWidget(self.filter_input)
        top_bar.addSpacing(10)
        top_bar.addWidget(self.start_btn)
        top_bar.addWidget(self.stop_btn)
        top_bar.addWidget(self.clear_btn)

        main_layout.addLayout(top_bar)

        # ---------------------------
        # ACTION BAR
        # ---------------------------
        action_bar = QHBoxLayout()

        self.action_label = QLabel("Diagnostics & Defense:")
        self.action_label.setFixedWidth(200)

        self.flush_btn = QPushButton("Flush DNS Cache")
        self.flush_btn.setIcon(QIcon(resource_path("icons/flush.png")))
        self.flush_btn.setIconSize(QSize(24, 24))
        self.flush_btn.setFixedHeight(38)
        self.flush_btn.clicked.connect(self.flush_dns)

        self.renew_btn = QPushButton("Renew IP Address")
        self.renew_btn.setIcon(QIcon(resource_path("icons/renew.png")))
        self.renew_btn.setIconSize(QSize(24, 24))
        self.renew_btn.setFixedHeight(38)
        self.renew_btn.clicked.connect(self.renew_ip)

        action_bar.addWidget(self.action_label)
        action_bar.addWidget(self.flush_btn)
        action_bar.addWidget(self.renew_btn)

        main_layout.addLayout(action_bar)

        # ---------------------------
        # STATUS BAR
        # ---------------------------
        self.status_label = QLabel("System Status: Ready. Please select an interface and click Start.")
        self.status_label.setAlignment(Qt.AlignLeft)
        self.status_label.setFixedHeight(28)
        main_layout.addWidget(self.status_label)

        # ---------------------------
        # PACKET TABLE
        # ---------------------------
        self.table = QTableWidget(0, 9)
        self.table.setHorizontalHeaderLabels([
            "Timestamp", "Source IP", "Destination IP", "Protocol",
            "Src Port", "Dst Port", "Length", "Severity", "Summary"
        ])

        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)

        self.table.setColumnWidth(0, 120)
        self.table.setColumnWidth(1, 180)
        self.table.setColumnWidth(2, 180)
        self.table.setColumnWidth(3, 90)
        self.table.setColumnWidth(4, 90)
        self.table.setColumnWidth(5, 90)
        self.table.setColumnWidth(6, 90)
        self.table.setColumnWidth(7, 150)
        self.table.setColumnWidth(8, 700)

        self.table.horizontalHeader().setStretchLastSection(True)

        main_layout.addWidget(self.table)
        self.setLayout(main_layout)

    def apply_style(self):
        self.setStyleSheet("""
            QWidget {
                background-color: #0a0f1e;
                color: #d8d8d8;
                font-family: Consolas;
                font-size: 13px;
            }

            QLabel {
                color: #ff4b7d;
                font-weight: bold;
            }

            QLineEdit {
                background-color: #10182d;
                border: 1px solid #2a3b6a;
                padding: 6px;
                border-radius: 4px;
                color: #ffffff;
                font-size: 13px;
            }

            QComboBox {
                background-color: #10182d;
                border: 1px solid #2a3b6a;
                padding: 5px;
                border-radius: 4px;
                color: white;
                font-size: 13px;
            }

            QPushButton {
                background-color: #e94057;
                border: none;
                padding: 6px;
                font-weight: bold;
                color: white;
                border-radius: 3px;
                font-size: 13px;
            }

            QPushButton:hover {
                background-color: #ff4b7d;
            }

            QPushButton:disabled {
                background-color: #444;
                color: #999;
            }

            QTableWidget {
                border: 1px solid #1d2b4f;
                gridline-color: #2a3b6a;
                font-size: 13px;
               border-image: url(""" + resource_path("terminal_pattern.png").replace("\\", "/") + """) 0 0 0 0 stretch stretch;

            }

            QHeaderView::section {
                background-color: #2d004d;
                color: #ffcc00;
                font-weight: bold;
                border: 1px solid #4a0080;
                padding: 7px;
                font-size: 13px;
            }
        """)

    # ---------------------------
    # BUTTON ACTIONS
    # ---------------------------
    def start_sniffing(self):
        iface = self.interface_box.currentText()

        if "No interfaces" in iface:
            QMessageBox.warning(self, "Error", "No valid network interface found.")
            return

        bpf_filter = self.filter_input.text().strip()
        if bpf_filter == "":
            bpf_filter = None

        self.status_label.setText("System Status: Running packet capture...")
        self.status_label.setStyleSheet("color: #00ffcc; font-weight: bold;")

        self.sniffer = SnifferThread(iface, bpf_filter, API_KEY)
        self.sniffer.packet_data = self.signal.packet_data
        self.sniffer.alert_signal = self.signal.alert_signal
        self.sniffer.start()

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

    def stop_sniffing(self):
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer.wait(1500)

        self.status_label.setText("System Status: Stopped.")
        self.status_label.setStyleSheet("color: orange; font-weight: bold;")

        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def clear_table(self):
        self.table.setRowCount(0)
        self.status_label.setText("System Status: Cleared packet table.")
        self.status_label.setStyleSheet("color: #00ffcc; font-weight: bold;")

    def flush_dns(self):
        msg = reset_network_settings("flushdns")
        QMessageBox.information(self, "Flush DNS Cache", msg)
        self.status_label.setText("System Status: DNS cache flushed.")
        self.status_label.setStyleSheet("color: #00ffcc; font-weight: bold;")

    def renew_ip(self):
        msg = reset_network_settings("renew")
        QMessageBox.information(self, "Renew IP Address", msg)
        self.status_label.setText("System Status: IP renewed.")
        self.status_label.setStyleSheet("color: #00ffcc; font-weight: bold;")

    # ---------------------------
    # TABLE UPDATE
    # ---------------------------
    def add_row(self, row):
        r = self.table.rowCount()
        self.table.insertRow(r)

        for c, val in enumerate(row):
            self.table.setItem(r, c, QTableWidgetItem(val))

        severity = row[7]

        if "CRITICAL" in severity:
           bg = QtGui.QColor("#e74c3c")
           fg = QtGui.QColor("white")

        elif "WARNING" in severity:
          bg = QtGui.QColor("#f39c12")
          fg = QtGui.QColor("black")

        elif "BLOCKED" in severity:
            bg = QtGui.QColor("#7b1e1e")  # dark red
            fg = QtGui.QColor("white")

        else:
             bg = QtGui.QColor("#05070d")
             fg = QtGui.QColor("white")


        for c in range(self.table.columnCount()):
            item = self.table.item(r, c)
            if item:
                item.setBackground(bg)
                item.setForeground(fg)

        self.table.scrollToBottom()

    # ---------------------------
    # ALERT HANDLER (FIXED)
    # ---------------------------
    def handle_alert(self, ip, mac, proto, port, reason):

        if ip in ["0.0.0.0", "-", "127.0.0.1", "::1"]:
            return

        now = time.time()

        # If already blocked, don't popup again
        if ip in self.alerted_ips:
            log_alert(ip, mac, proto, port, reason)
            return

        # Cooldown check (avoid popup spam)
        if ip in self.last_alert_time:
            if now - self.last_alert_time[ip] < self.alert_cooldown:
                log_alert(ip, mac, proto, port, reason)
                return

        self.last_alert_time[ip] = now

        log_alert(ip, mac, proto, port, reason)
        block_ip(ip)

        self.alerted_ips.add(ip)

        self.status_label.setText(f"System Status: 🚨 THREAT BLOCKED ({ip})")
        self.status_label.setStyleSheet("color: red; font-weight: bold;")

        QMessageBox.critical(
            self,
            "SECURITY ALERT",
            f"🚨 CRITICAL THREAT DETECTED!\n\n"
            f"Reason: {reason}\n"
            f"Attacker IP: {ip}\n"
            f"Attacker MAC: {mac}\n"
            f"Protocol: {proto}/{port}\n\n"
            f"Action Taken: IP BLOCKED"
        )


if __name__ == "__main__":
    app = QApplication(sys.argv)
    gui = CyberSniffer()
    gui.show()
    sys.exit(app.exec_())
