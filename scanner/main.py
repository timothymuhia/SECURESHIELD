import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QVBoxLayout, QLineEdit,
    QPushButton, QTextEdit, QMessageBox, QFileDialog, QHBoxLayout
)
from PyQt5.QtGui import QFont, QColor, QTextCursor
from PyQt5.QtCore import Qt, QTimer
from scanner_core import scan_website

class ScannerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Cyber Security Website Scanner")
        self.setGeometry(100, 100, 750, 550)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()

        self.title = QLabel("Cyber Security Website Scanner")
        self.title.setFont(QFont("Arial", 20, QFont.Bold))
        self.title.setStyleSheet("color: #00c896")
        self.title.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.title)

        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Enter website URL (e.g. https://example.com)")
        self.url_input.setFont(QFont("Arial", 12))
        layout.addWidget(self.url_input)

        button_layout = QHBoxLayout()

        self.scan_button = QPushButton("🔍 Scan Website")
        self.scan_button.setFont(QFont("Arial", 12))
        self.scan_button.setStyleSheet("background-color: #00c896; color: white")
        self.scan_button.clicked.connect(self.start_scan)
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

    def start_scan(self):
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "Input Error", "Please enter a website URL.")
            return

        self.result_box.setText("⏳ Scanning in progress...\n")
        self.scan_button.setEnabled(False)
        QApplication.setOverrideCursor(Qt.WaitCursor)

        QTimer.singleShot(100, lambda: self.perform_scan(url))

    def perform_scan(self, url):
        try:
            results = scan_website(url)
            self.display_results(results)
            self.save_button.setEnabled(True)
        except Exception as e:
            self.result_box.setText(f"❌ Error during scan:\n{str(e)}")

        self.scan_button.setEnabled(True)
        QApplication.restoreOverrideCursor()

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
