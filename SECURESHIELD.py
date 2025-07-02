import sys
import os
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QLineEdit,
    QPushButton, QTextEdit, QStatusBar, QProgressBar, QMessageBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QColor

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    # Correct import for the package structure
    from scanner import backend_scanner as scanner
except ImportError as e:
    print(f"Import error: {e}")
    # Show an error message if the import fails
    app = QApplication(sys.argv)
    QMessageBox.critical(
        None,
        "Critical Import Error",
        f"Failed to import scanner module: {str(e)}\n\n"
        "Please make sure:\n"
        "1. You have a 'scanner' folder in the same directory\n"
        "2. It contains '__init__.py' and 'backend_scanner.py' files\n"
        "3. The functions are properly defined in backend_scanner.py\n\n"
        "Application will now exit."
    )
    sys.exit(1)

class ScanThread(QThread):
    progress = pyqtSignal(int, str)
    result = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, url):
        super().__init__()
        self.url = url

    def run(self):
        try:
            # Run security checks
            self.progress.emit(20, "Checking security headers...")
            headers_report = scanner.check_security_headers(self.url)
            
            self.progress.emit(40, "Scanning links for malicious content...")
            links_report = scanner.extract_and_check_links(self.url)
            
            self.progress.emit(60, "Scanning for open ports...")
            ports_report = scanner.basic_port_scan(self.url)
            
            # Generate final report
            report = f"📄 SECURITY SCAN REPORT FOR: {self.url}\n"
            report += "=" * 80 + "\n"
            report += headers_report + "\n"
            report += links_report + "\n"
            report += ports_report + "\n"
            report += "=" * 80 + "\nScan complete!"
            
            self.result.emit(report)
        except Exception as e:
            self.result.emit(f"❌ Error occurred during scan: {str(e)}")
        finally:
            self.finished.emit()

class SECURESHIELDApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SECURESHIELD - Website Security Scanner")
        self.setGeometry(100, 100, 800, 600)
        
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Create layout
        layout = QVBoxLayout()
        central_widget.setLayout(layout)
        
        # Title
        title = QLabel("SECURESHIELD - Website Security Scanner")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 16pt; font-weight: bold; margin-bottom: 20px;")
        layout.addWidget(title)
        
        # URL input
        url_layout = QVBoxLayout()
        url_label = QLabel("Enter website URL to scan:")
        url_label.setStyleSheet("font-weight: bold;")
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com")
        url_layout.addWidget(url_label)
        url_layout.addWidget(self.url_input)
        layout.addLayout(url_layout)
        
        # Scan button
        self.scan_button = QPushButton("Start Security Scan")
        self.scan_button.setStyleSheet(
            "background-color: #4CAF50; color: white; font-weight: bold; padding: 10px;"
        )
        self.scan_button.clicked.connect(self.start_scan)
        layout.addWidget(self.scan_button)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Status label
        self.status_label = QLabel()
        self.status_label.setVisible(False)
        self.status_label.setStyleSheet("font-style: italic;")
        layout.addWidget(self.status_label)
        
        # Results area
        results_label = QLabel("Scan Results:")
        results_label.setStyleSheet("font-weight: bold; margin-top: 20px;")
        layout.addWidget(results_label)
        
        self.results_area = QTextEdit()
        self.results_area.setReadOnly(True)
        self.results_area.setStyleSheet("font-family: monospace;")
        layout.addWidget(self.results_area)
        
        # Status bar
        self.statusBar().showMessage("Ready")
        
        # Initialize thread
        self.scan_thread = None

    def start_scan(self):
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "Input Error", "Please enter a valid URL")
            return
        
        # Disable UI during scan
        self.url_input.setEnabled(False)
        self.scan_button.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.status_label.setVisible(True)
        self.progress_bar.setValue(0)
        self.status_label.setText("Initializing scan...")
        self.statusBar().showMessage(f"Scanning {url}...")
        self.results_area.clear()
        
        # Create and start scan thread
        self.scan_thread = ScanThread(url)
        self.scan_thread.progress.connect(self.update_progress)
        self.scan_thread.result.connect(self.show_results)
        self.scan_thread.finished.connect(self.scan_finished)
        self.scan_thread.start()

    def update_progress(self, value, message):
        self.progress_bar.setValue(value)
        self.status_label.setText(message)
        self.statusBar().showMessage(message)

    def show_results(self, report):
        # Format results with colors
        formatted_report = report
        formatted_report = formatted_report.replace("✅", '<font color="green">✅</font>')
        formatted_report = formatted_report.replace("❌", '<font color="red">❌</font>')
        formatted_report = formatted_report.replace("⚠️", '<font color="orange">⚠️</font>')
        formatted_report = formatted_report.replace("🔴", '<font color="red">🔴</font>')
        formatted_report = formatted_report.replace("🟢", '<font color="green">🟢</font>')
        formatted_report = formatted_report.replace("🟠", '<font color="orange">🟠</font>')
        formatted_report = formatted_report.replace("🔓", '<font color="red">🔓</font>')
        formatted_report = formatted_report.replace("🔒", '<font color="green">🔒</font>')
        formatted_report = formatted_report.replace("\n", "<br>")
        
        self.results_area.setHtml(f"<pre>{formatted_report}</pre>")

    def scan_finished(self):
        # Re-enable UI
        self.url_input.setEnabled(True)
        self.scan_button.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.status_label.setVisible(False)
        self.statusBar().showMessage("Scan complete!")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SECURESHIELDApp()
    window.show()
    sys.exit(app.exec_())