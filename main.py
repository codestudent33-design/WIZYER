from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import matplotlib.pyplot as plt
import re
import sys
import platform
import subprocess
import json
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional
import shutil

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QTableWidget, QTableWidgetItem, QTabWidget, QFileDialog, QLabel, QTextEdit,
    QProgressBar, QMessageBox, QHeaderView, QComboBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    REPORTLAB_AVAILABLE = True
except Exception:
    REPORTLAB_AVAILABLE = False


# ---------------------- COMMAND ----------------------

def run_cmd(cmd: List[str]) -> str:
    out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
    return out.decode(errors='ignore')


# ---------------------- INTELLIGENT MODEL ----------------------

def intelligent_risk_analysis(networks):
    ssid_count = {}

    for n in networks:
        ssid = n.get('ssid') or '<hidden>'
        ssid_count[ssid] = ssid_count.get(ssid, 0) + 1

    for n in networks:
        score = 0
        reasons = []
        recommendations = []

        ssid = n.get('ssid') or '<hidden>'
        security = (n.get('security') or '').upper()
        signal = n.get('signal')

        # Layer 1
        if 'OPEN' in security:
            score += 50
            reasons.append("Open network → no authentication")
            recommendations.append("Use WPA3")

        elif 'WEP' in security:
            score += 40
            reasons.append("WEP → easily crackable")
            recommendations.append("Upgrade to WPA3")

        elif 'WPA2' in security:
            score += 20
            reasons.append("WPA2 → vulnerable to dictionary attacks")
            recommendations.append("Use WPA3 + strong password")

        elif 'WPA3' in security:
            score += 5
            reasons.append("WPA3 → strong security")
            recommendations.append("Keep using WPA3")

        # Layer 2
        if not n.get('ssid'):
            score += 15
            reasons.append("Hidden SSID → not truly secure")
            recommendations.append("Do not rely on hidden SSID")

        # Layer 3
        if ssid_count.get(ssid, 0) > 1:
            score += 25
            reasons.append("Duplicate SSID → possible Evil Twin")
            recommendations.append("Verify BSSID before connecting")

        # Layer 4
        try:
            if signal:
                val = int(str(signal).replace('%', ''))
                if val > 85:
                    score += 15
                    reasons.append("Very strong signal → suspicious")
                    recommendations.append("Check for fake hotspot")
        except:
            pass

        # Final Risk
        if score >= 60:
            risk = 'HIGH'
        elif score >= 30:
            risk = 'MEDIUM'
        else:
            risk = 'LOW'

        n['risk'] = risk
        n['score'] = score
        n['reason'] = " | ".join(reasons)
        n['recommendation'] = " | ".join(recommendations)

    return networks


def calculate_score(networks):
    if not networks:
        return 0

    total = 0
    for n in networks:
        if n['risk'] == 'LOW':
            total += 90
        elif n['risk'] == 'MEDIUM':
            total += 60
        else:
            total += 30

    return int(total / len(networks))


def severity_color(sev):
    if sev == 'HIGH':
        return Qt.red
    if sev == 'MEDIUM':
        return Qt.darkYellow
    if sev == 'LOW':
        return Qt.green
    return Qt.lightGray


# ---------------------- PARSER ----------------------

def parse_netsh_output(raw):
    networks = []
    lines = raw.splitlines()
    cur = None

    for line in lines:
        s = line.strip()

        if s.startswith('SSID') and ':' in s and 'BSSID' not in s:
            cur = {
                'ssid': s.split(':', 1)[1].strip(),
                'bssid': '',
                'security': '',
                'channel': '',
                'signal': ''
            }
            networks.append(cur)

        elif 'BSSID' in s and cur:
            cur['bssid'] = s.split(':', 1)[1].strip()

        elif 'Authentication' in s and cur:
            cur['security'] = s.split(':', 1)[1].strip()

        elif 'Signal' in s and cur:
            cur['signal'] = s.split(':', 1)[1].strip()

        elif 'Channel' in s and cur:
            cur['channel'] = s.split(':', 1)[1].strip()

    return networks


# ---------------------- THREAD ----------------------

class SystemScanThread(QThread):
    finished_signal = pyqtSignal(list)
    log_signal = pyqtSignal(str)

    def run(self):
        try:
            raw = run_cmd(['netsh', 'wlan', 'show', 'networks', 'mode=bssid'])
            networks = parse_netsh_output(raw)
        except:
            networks = []

        networks = intelligent_risk_analysis(networks)
        self.finished_signal.emit(networks)


# ---------------------- GUI ----------------------

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("WIZYER – WiFi Security Analyzer & Risk Assessment System")
        self.resize(1100, 700)

        self.scan_results = []

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.scan_tab = QWidget()
        self.report_tab = QWidget()

        self.build_scan_tab()
        self.build_report_tab()

        self.tabs.addTab(self.scan_tab, "Live Scan")
        self.tabs.addTab(self.report_tab, "Reports")

    def build_scan_tab(self):
        layout = QVBoxLayout()

        self.scan_btn = QPushButton("Start Scan")
        self.scan_btn.clicked.connect(self.start_scan)
        layout.addWidget(self.scan_btn)

        self.table = QTableWidget(0, 8)
        self.table.setHorizontalHeaderLabels([
            'SSID','BSSID','Security','Channel','Signal',
            'Risk','Reason & Vulnerability','Recommendation'
        ])
        layout.addWidget(self.table)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.Stretch)
        header.setSectionResizeMode(7, QHeaderView.Stretch)

        self.progress = QProgressBar()
        layout.addWidget(self.progress)

        self.scan_tab.setLayout(layout)

    def build_report_tab(self):
        layout = QVBoxLayout()

        self.score_label = QLabel("Final Security Score: --/100")
        self.score_label.setAlignment(Qt.AlignCenter)
        self.score_label.setStyleSheet("font-size:18px; font-weight:bold;")
        layout.addWidget(self.score_label)

        self.report_preview = QTextEdit()
        self.report_preview.setReadOnly(True)
        self.report_preview.setStyleSheet(
             "background-color: white; color: black; font-family: Consolas; font-size: 11px;"
)
        layout.addWidget(self.report_preview)

        self.figure = plt.figure()
        self.canvas = FigureCanvas(self.figure)
        layout.addWidget(self.canvas)

        self.report_tab.setLayout(layout)

    def start_scan(self):
        self.progress.setValue(5)
        self.thread = SystemScanThread()
        self.thread.finished_signal.connect(self.scan_finished)
        self.thread.start()

    def scan_finished(self, networks):
        self.progress.setValue(100)
        self.scan_results = networks
        self.populate_table()
        self.generate_report_preview()
        self.update_dashboard()
        self.update_score()

    def populate_table(self):
        self.table.setRowCount(0)

        for n in self.scan_results:
            row = self.table.rowCount()
            self.table.insertRow(row)

            self.table.setItem(row,0,QTableWidgetItem(n.get('ssid','')))
            self.table.setItem(row,1,QTableWidgetItem(n.get('bssid','')))
            self.table.setItem(row,2,QTableWidgetItem(n.get('security','')))
            self.table.setItem(row,3,QTableWidgetItem(n.get('channel','')))
            self.table.setItem(row,4,QTableWidgetItem(n.get('signal','')))

            risk_item = QTableWidgetItem(n.get('risk'))
            risk_item.setBackground(severity_color(n.get('risk')))
            self.table.setItem(row,5,risk_item)

            self.table.setItem(row,6,QTableWidgetItem(n.get('reason')))
            self.table.setItem(row,7,QTableWidgetItem(n.get('recommendation')))

    def update_dashboard(self):
        low = sum(1 for n in self.scan_results if n['risk']=='LOW')
        med = sum(1 for n in self.scan_results if n['risk']=='MEDIUM')
        high = sum(1 for n in self.scan_results if n['risk']=='HIGH')

        self.figure.clear()
        ax = self.figure.add_subplot(111)
        ax.bar(['LOW','MEDIUM','HIGH'], [low,med,high])
        ax.set_title("Network Risk Distribution")

        self.canvas.draw()

    def update_score(self):
        score = calculate_score(self.scan_results)
        self.score_label.setText(f"Final Security Score: {score}/100")

    def generate_report_preview(self):
        report = {
        'generated': datetime.now(timezone.utc).isoformat(),
        'final_security_score': calculate_score(self.scan_results),
        'scans': []
    }

        if self.scan_results:
            report['scans'].append({
            'type': 'system',
            'networks': self.scan_results
            })

        text = json.dumps(report, indent=2)
        self.report_preview.setText(text)


# ---------------------- MAIN ----------------------

def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()