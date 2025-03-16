import requests
import logging

logger = logging.getLogger(__name__)

class LoggingMonitoringScanner:
    def __init__(self, path, method, get_params, post_body):
        self.path = path
        self.method = method
        self.get_params = get_params
        self.post_body = post_body
        self.session = requests.Session()
        self.findings = []

    def scan(self):
        try:
            if self.method == 'GET' and 'login' in self.path.lower():
                url = f"{self.path}?user=admin&pass=wrong"
                response = self.session.get(url)
                if response.status_code == 401 and "log" not in response.text.lower():
                    finding = {
                        'type': 'Insufficient Logging (A10)',
                        'severity': 'Medium',
                        'description': 'No indication of logging for failed login attempts',
                        'reproduce': f'GET {url}',
                        'mitigation': 'Implement logging for all sensitive actions'
                    }
                    self.findings.append(finding)
                    # Real-time output
                    print(f"[VULN] {finding['type']} - Severity: {finding['severity']}")
                    print(f"  Description: {finding['description']}")
                    print(f"  Steps to Reproduce: {finding['reproduce']}")
                    print(f"  Mitigation: {finding['mitigation']}\n")
                    logger.info(f"Found: Insufficient Logging at {url}")
        except requests.RequestException:
            pass
        return self.findings