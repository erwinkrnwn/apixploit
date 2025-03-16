import requests
import logging

logger = logging.getLogger(__name__)

class BrokenAccessScanner:
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
                if "admin" in response.text.lower() and response.status_code == 200:
                    finding = {
                        'type': 'Broken Access Control (A5)',
                        'severity': 'High',
                        'description': 'Access to data without authorization',
                        'reproduce': f'GET {self.path}',
                        'mitigation': 'Implement role-based access control'
                    }
                    self.findings.append(finding)
                    # Real-time output
                    print(f"[VULN] {finding['type']} - Severity: {finding['severity']}")
                    print(f"  Description: {finding['description']}")
                    print(f"  Steps to Reproduce: {finding['reproduce']}")
                    print(f"  Mitigation: {finding['mitigation']}\n")
                    logger.info(f"Found: Broken Access Control at {self.path}")
        except requests.RequestException:
            pass
        return self.findings