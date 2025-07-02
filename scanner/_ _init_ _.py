# This makes the scanner directory a Python package
from .backend_scanner import (
    check_security_headers,
    extract_and_check_links,
    basic_port_scan
)