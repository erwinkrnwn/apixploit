import requests
import logging

logger = logging.getLogger(__name__)

class PassiveScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.findings = []

    def scan(self):
        try:
            response = self.session.get(self.target_url)
            self.check_headers(response.headers)
            return self.findings
        except requests.RequestException as e:
            logger.error(f"Passive scan error: {str(e)}")
            return []

    def check_headers(self, headers):
        security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'Content-Security-Policy': None
        }
        for header, expected in security_headers.items():
            if header not in headers or (expected and headers[header] != expected):
                finding = {
                    'type': f'Missing/Insecure {header}',
                    'severity': 'Medium',
                    'description': f'{header} header is not properly configured',
                    'reproduce': f'GET {self.target_url} (check headers)',
                    'mitigation': f'Configure {header} correctly'
                }
                self.findings.append(finding)
                # Real-time output
                print(f"[VULN] {finding['type']} - Severity: {finding['severity']}")
                print(f"  Description: {finding['description']}")
                print(f"  Steps to Reproduce: {finding['reproduce']}")
                print(f"  Mitigation: {finding['mitigation']}\n")
                logger.warning(f"Found: Missing/Insecure {header}")