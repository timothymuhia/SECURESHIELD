import sys
import socket
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QVBoxLayout, QLineEdit,
    QPushButton, QTextEdit, QMessageBox, QFileDialog, QHBoxLayout
)
from PyQt5.QtGui import QFont, QColor, QTextCursor
from PyQt5.QtCore import Qt, QTimer

class ScannerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SECURESHIELD")
        self.setGeometry(100, 100, 750, 600)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()

        self.title = QLabel("SECURESHIELD")
        self.title.setFont(QFont("Arial", 20, QFont.Bold))
        self.title.setStyleSheet("color: #00c896")
        self.title.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.title)

        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Enter website URL (e.g. https://example.com)")
        self.url_input.setFont(QFont("Arial", 12))
        layout.addWidget(self.url_input)

        button_layout = QHBoxLayout()

        self.scan_button = QPushButton("🔍 Full Scan")
        self.scan_button.setFont(QFont("Arial", 12))
        self.scan_button.setStyleSheet("background-color: #00c896; color: white")
        self.scan_button.clicked.connect(self.start_full_scan)
        button_layout.addWidget(self.scan_button)

        self.save_button = QPushButton("💾 Save Results")
        self.save_button.setFont(QFont("Arial", 12))
        self.save_button.setStyleSheet("background-color: #444; color: white")
        self.save_button.clicked.connect(self.save_results)
        self.save_button.setEnabled(False)
        button_layout.addWidget(self.save_button)

        layout.addLayout(button_layout)

        self.result_box = QTextEdit()
        self.result_box.setReadOnly(True)
        self.result_box.setFont(QFont("Courier New", 11))
        self.result_box.setStyleSheet("background-color: #1e1e1e; color: white")
        layout.addWidget(self.result_box)

        self.setLayout(layout)

    def start_full_scan(self):
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "Input Error", "Please enter a website URL.")
            return

        self.result_box.setText("⏳ Scanning in progress...\n")
        self.scan_button.setEnabled(False)
        QApplication.setOverrideCursor(Qt.WaitCursor)

        QTimer.singleShot(100, lambda: self.perform_full_scan(url))

    def perform_full_scan(self, url):
        try:
            web_results = (url)
            port_results = self.perform_port_scan(url)
            results = web_results + "\n" + port_results
            self.display_results(results)
            self.save_button.setEnabled(True)
        except Exception as e:
            self.result_box.setText(f"❌ Error during scan:\n{str(e)}")

        self.scan_button.setEnabled(True)
        QApplication.restoreOverrideCursor()

    def perform_port_scan(self, url):
        result = ["\n🔌 Starting basic port scan (Top 10 common ports)...\n"]
        try:
            host = url.replace("http://", "").replace("https://", "").split("/")[0]
            common_ports = {
                21: "FTP",
                22: "SSH",
                23: "Telnet",
                25: "SMTP",
                53: "DNS",
                80: "HTTP",
                110: "POP3",
                143: "IMAP",
                443: "HTTPS",
                3306: "MySQL"
            }
            for port, service in common_ports.items():
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result_code = sock.connect_ex((host, port))
                if result_code == 0:
                    result.append(f"✅ Port {port} ({service}) is OPEN\n")
                else:
                    result.append(f"⚠️ Port {port} ({service}) is CLOSED\n")
                sock.close()
        except Exception as e:
            result.append(f"❌ Port scan failed: {str(e)}\n")

        return ''.join(result)

    def display_results(self, results):
        self.result_box.clear()
        for line in results.split('\n'):
            if "✅" in line:
                self.result_box.setTextColor(QColor("lime"))
            elif "⚠️" in line:
                self.result_box.setTextColor(QColor("orange"))
            elif "❌" in line or "🚨" in line:
                self.result_box.setTextColor(QColor("red"))
            else:
                self.result_box.setTextColor(QColor("white"))
            self.result_box.append(line)
        self.result_box.moveCursor(QTextCursor.Start)

    def save_results(self):
        text = self.result_box.toPlainText()
        if not text.strip():
            QMessageBox.information(self, "No Data", "Nothing to save.")
            return

        filename, _ = QFileDialog.getSaveFileName(self, "Save Results", "scan_results.txt", "Text Files (*.txt)")
        if filename:
            with open(filename, 'w', encoding='utf-8') as file:
                file.write(text)
            QMessageBox.information(self, "Saved", f"Scan results saved to:\n{filename}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ScannerApp()
    window.show()
    sys.exit(app.exec_())
