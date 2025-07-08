from scanner.backend_scanner import check_security_headers, basic_port_scan

print("=== TESTING SECURITY HEADERS ===")
print(check_security_headers("https://rvibs.ac.ke"))

print("\n=== TESTING PORT SCAN ===")
print(basic_port_scan("example.com"))

print("\n=== TEST COMPLETE ===")