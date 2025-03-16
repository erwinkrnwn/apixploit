import requests
import logging

logger = logging.getLogger(__name__)

class BrokenAuthScanner:
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
                if response.status_code == 200 and "admin" in response.text.lower():
                    finding = {
                        'type': 'Broken Authentication (A2)',
                        'severity': 'High',
                        'description': 'Endpoint accessible without authentication',
                        'reproduce': f'GET {self.path}',
                        'mitigation': 'Implement strong authentication and session management'
                    }
                    self.findings.append(finding)
                    # Real-time output
                    print(f"[VULN] {finding['type']} - Severity: {finding['severity']}")
                    print(f"  Description: {finding['description']}")
                    print(f"  Steps to Reproduce: {finding['reproduce']}")
                    print(f"  Mitigation: {finding['mitigation']}\n")
                    logger.info(f"Found: Broken Authentication at {self.path}")
        except requests.RequestException:
            pass
        return self.findings