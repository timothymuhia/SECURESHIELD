import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QVBoxLayout, QLineEdit,
    QPushButton, QTextEdit, QMessageBox
)
from PyQt5.QtGui import QFont
from scanner_core import scan_website

class ScannerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SRCURESHIELD")
        self.setGeometry(100, 100, 700, 500)

        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()

        self.title = QLabel("SECURESHIELD")
        self.title.setFont(QFont("Arial", 18, QFont.Bold))
        layout.addWidget(self.title)

        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Enter website URL (e.g. https://example.com)")
        layout.addWidget(self.url_input)

        self.scan_button = QPushButton("Scan Website")
        self.scan_button.clicked.connect(self.start_scan)
        layout.addWidget(self.scan_button)

        self.result_box = QTextEdit()
        self.result_box.setReadOnly(True)
        self.result_box.setFont(QFont("Courier", 10))
        layout.addWidget(self.result_box)

        self.setLayout(layout)

    def start_scan(self):
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "Input Error", "Please enter a website URL.")
            return

        self.result_box.setText("🔄 Scanning in progress...\n")
        try:
            results = scan_website(url)
            self.result_box.setText(results)
        except Exception as e:
            self.result_box.setText(f"❌ Error during scan:\n{str(e)}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ScannerApp()
    window.show()
    sys.exit(app.exec_())
