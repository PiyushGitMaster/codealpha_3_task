import logging
from typing import List, Dict, Pattern
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class PacketAnalyzer:
    """Analyzes network packet payloads against predefined suspicious signatures."""

    def __init__(self):
        # Define basic signatures, e.g., for detecting potential HTTP/SQL injection or remote shell attempts
        self.signatures: List[Dict[str, Pattern]] = [
            {'name': 'SQL Injection attempt', 'pattern': re.compile(b"(UNION SELECT|CHAR\(|ORDER BY)", re.IGNORECASE)},
            {'name': 'Directory Traversal', 'pattern': re.compile(b"(\.\.\/|\.\.\\)", re.IGNORECASE)},
            {'name': 'Reverse Shell attempt', 'pattern': re.compile(b"(/bin/sh|/bin/bash|cmd.exe)", re.IGNORECASE)},
            {'name': 'Suspect User-Agent', 'pattern': re.compile(b"User-Agent: (sqlmap|nikto|w3af)", re.IGNORECASE)}
        ]

    def analyze_payload(self, payload: bytes) -> bool:
        """
        Scans a raw byte payload against loaded signatures.

        Args:
            payload: The raw data payload from a network packet.

        Returns:
            bool: True if suspicious content is found, False otherwise.
        """
        if not payload:
            return False

        for sig in self.signatures:
            if sig['pattern'].search(payload):
                logging.warning(f"ALERT: Discovered {sig['name']} in packet payload!")
                return True
        return False

if __name__ == "__main__":
    # Internal test cases
    analyzer = PacketAnalyzer()
    
    test_clean = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    test_sql = b"GET /product?id=1' UNION SELECT username, password FROM users-- HTTP/1.1\r\nHost: example.com\r\n\r\n"
    test_traversal = b"GET /../../../../etc/passwd HTTP/1.1\r\nHost: example.com\r\n\r\n"

    print("Testing clean payload...")
    if not analyzer.analyze_payload(test_clean):
        print("Result: Clean")

    print("\nTesting SQL injection payload...")
    if analyzer.analyze_payload(test_sql):
        print("Result: Suspicious")

    print("\nTesting Directory Traversal payload...")
    if analyzer.analyze_payload(test_traversal):
        print("Result: Suspicious")