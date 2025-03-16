import requests
import logging

logger = logging.getLogger(__name__)

class ComponentsScanner:
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
                server = response.headers.get('Server', '')
                if "Apache/2.2" in server:
                    finding = {
                        'type': 'Known Vulnerable Components (A9)',
                        'severity': 'Medium',
                        'description': f'Server version {server} has known vulnerabilities',
                        'reproduce': f'GET {self.path} (check Server header)',
                        'mitigation': 'Update components to the latest version'
                    }
                    self.findings.append(finding)
                    # Real-time output
                    print(f"[VULN] {finding['type']} - Severity: {finding['severity']}")
                    print(f"  Description: {finding['description']}")
                    print(f"  Steps to Reproduce: {finding['reproduce']}")
                    print(f"  Mitigation: {finding['mitigation']}\n")
                    logger.info(f"Found: Known Vulnerable Components at {self.path}")
        except requests.RequestException:
            pass
        return self.findings