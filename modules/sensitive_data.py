import requests
import logging

logger = logging.getLogger(__name__)

class SensitiveDataScanner:
    def __init__(self, path, method, get_params, post_body):
        self.path = path
        self.method = method
        self.get_params = get_params
        self.post_body = post_body
        self.session = requests.Session()
        self.findings = []

    def scan(self):
        try:
            if self.method == 'GET':
                response = self.session.get(self.path)
                if "password" in response.text.lower() or "credit_card" in response.text.lower():
                    finding = {
                        'type': 'Sensitive Data Exposure (A3)',
                        'severity': 'High',
                        'description': 'Sensitive data exposed in response',
                        'reproduce': f'GET {self.path}',
                        'mitigation': 'Encrypt sensitive data'
                    }
                    self.findings.append(finding)
                    # Real-time output
                    print(f"[VULN] {finding['type']} - Severity: {finding['severity']}")
                    print(f"  Description: {finding['description']}")
                    print(f"  Steps to Reproduce: {finding['reproduce']}")
                    print(f"  Mitigation: {finding['mitigation']}\n")
                    logger.info(f"Found: Sensitive Data Exposure at {self.path}")
        except requests.RequestException:
            pass
        return self.findings