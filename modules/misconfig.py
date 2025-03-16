import requests
import logging

logger = logging.getLogger(__name__)

class MisconfigScanner:
    def __init__(self, path, method, get_params, post_body):
        self.path = path
        self.method = method
        self.get_params = get_params
        self.post_body = post_body
        self.session = requests.Session()
        self.findings = []

    def scan(self):
        try:
            if self.method == 'GET' and '.env' in self.path:
                response = self.session.get(self.path)
                if "DB_PASSWORD" in response.text:
                    finding = {
                        'type': 'Security Misconfiguration (A6)',
                        'severity': 'High',
                        'description': 'Sensitive configuration file exposed',
                        'reproduce': f'GET {self.path}',
                        'mitigation': 'Restrict access to configuration files'
                    }
                    self.findings.append(finding)
                    # Real-time output
                    print(f"[VULN] {finding['type']} - Severity: {finding['severity']}")
                    print(f"  Description: {finding['description']}")
                    print(f"  Steps to Reproduce: {finding['reproduce']}")
                    print(f"  Mitigation: {finding['mitigation']}\n")
                    logger.info(f"Found: Security Misconfiguration at {self.path}")
        except requests.RequestException:
            pass
        return self.findings