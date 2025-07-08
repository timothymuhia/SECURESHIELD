import sys
import socket
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QVBoxLayout, QLineEdit,
    QPushButton, QTextEdit, QMessageBox, QFileDialog, QHBoxLayout
)
from PyQt5.QtGui import QFont, QColor, QTextCursor
from PyQt5.QtCore import Qt, QTimer
from urllib.parse import urlparse  # Added this import
from backend_scanner import scan_website

class ScannerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Cyber Security Website Scanner")
        self.setGeometry(100, 100, 800, 650)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()

        # Header
        self.title = QLabel("Website Security Scanner")
        self.title.setFont(QFont("Arial", 20, QFont.Bold))
        self.title.setStyleSheet("color: #2ecc71")
        self.title.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.title)

        # URL Input
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Enter website URL (e.g. example.com)")
        self.url_input.setFont(QFont("Arial", 12))
        layout.addWidget(self.url_input)

        # Buttons
        button_layout = QHBoxLayout()
        
        self.scan_button = QPushButton("🔍 Full Scan")
        self.scan_button.setFont(QFont("Arial", 12, QFont.Bold))
        self.scan_button.setStyleSheet("background-color: #2ecc71; color: white; padding: 8px")
        self.scan_button.clicked.connect(self.start_full_scan)
        button_layout.addWidget(self.scan_button)

        self.save_button = QPushButton("💾 Save Results")
        self.save_button.setFont(QFont("Arial", 12))
        self.save_button.setStyleSheet("background-color: #34495e; color: white; padding: 8px")
        self.save_button.clicked.connect(self.save_results)
        self.save_button.setEnabled(False)
        button_layout.addWidget(self.save_button)

        layout.addLayout(button_layout)

        # Results Display
        self.result_box = QTextEdit()
        self.result_box.setReadOnly(True)
        self.result_box.setFont(QFont("Courier New", 11))
        self.result_box.setStyleSheet("background-color: #2c3e50; color: #ecf0f1; padding: 10px")
        layout.addWidget(self.result_box)

        self.setLayout(layout)

    def start_full_scan(self):
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "Error", "Please enter a website URL")
            return

        self.result_box.clear()
        self.scan_button.setEnabled(False)
        QApplication.setOverrideCursor(Qt.WaitCursor)
        
        QTimer.singleShot(100, lambda: self.run_scans(url))

    def run_scans(self, url):
        try:
            # Run website scan
            web_results = scan_website(url)
            self.display_results(web_results)
            
            # Run port scan
            port_results = self.perform_port_scan(url)
            self.display_results(port_results)
            
            self.save_button.setEnabled(True)
        except Exception as e:
            self.result_box.append(f"❌ Error: {str(e)}")
        finally:
            self.scan_button.setEnabled(True)
            QApplication.restoreOverrideCursor()

    def perform_port_scan(self, url):
        """Scan top 10 common ports"""
        result = ["\n🔌 Scanning Top 10 Ports:\n"]
        
        try:
            # Extract hostname
            parsed = urlparse(url if '://' in url else f'http://{url}')
            host = parsed.hostname or url.split('/')[0]
            
            if not host:
                return "\n⚠️ Invalid host for port scanning\n"
            
            result.append(f"📡 Target: {host}\n\n")
            
            # Top 10 common ports
            ports = {
                21: "FTP",
                22: "SSH", 
                80: "HTTP",
                443: "HTTPS",
                3306: "MySQL",
                3389: "RDP",
                53: "DNS",
                25: "SMTP", 
                110: "POP3",
                143: "IMAP"
            }
            
            for port, service in ports.items():
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(1.5)
                        if s.connect_ex((host, port)) == 0:
                            result.append(f"🚨 OPEN: {port} ({service})\n")
                        else:
                            result.append(f"✅ Closed: {port} ({service})\n")
                except:
                    result.append(f"⚠️ Error checking {port}\n")
            
            return ''.join(result)
        
        except Exception as e:
            return f"\n❌ Port scan failed: {str(e)}\n"

    def display_results(self, text):
        cursor = self.result_box.textCursor()
        cursor.movePosition(QTextCursor.End)
        
        for line in text.split('\n'):
            if "✅" in line or "Present:" in line:
                self.result_box.setTextColor(QColor("#2ecc71"))  # Green
            elif "⚠️" in line:
                self.result_box.setTextColor(QColor("#f39c12"))  # Orange
            elif "🚨" in line or "OPEN:" in line:
                self.result_box.setTextColor(QColor("#e74c3c"))  # Red
            else:
                self.result_box.setTextColor(QColor("#ecf0f1"))  # White
            
            cursor.insertText(line + '\n')
        
        self.result_box.ensureCursorVisible()

    def save_results(self):
        text = self.result_box.toPlainText()
        if not text.strip():
            QMessageBox.information(self, "Info", "No results to save")
            return

        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Save Scan Results",
            "scan_results.txt",
            "Text Files (*.txt);;All Files (*)"
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(text)
                QMessageBox.information(self, "Saved", f"Results saved to:\n{filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save:\n{str(e)}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    window = ScannerApp()
    window.show()
    sys.exit(app.exec_())