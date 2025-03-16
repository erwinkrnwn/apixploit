import requests
import logging
import json
import html

logger = logging.getLogger(__name__)

class HHIScanner:
    def __init__(self, path, method, get_params, post_body):
        self.path = path
        self.method = method
        self.get_params = get_params
        self.post_body = post_body
        self.session = requests.Session()
        self.findings = []
        self.hhi_steps = []

    def scan(self):
        malicious_host = "evil.com"
        headers = {'Host': malicious_host}
        
        # Test GET
        if self.method == 'GET':
            try:
                response = self.session.get(self.path, headers=headers, timeout=5)
                if response.status_code in [200, 301, 302] and malicious_host in response.text:
                    self.hhi_steps.append(f'GET {self.path} with Host: {malicious_host}')
            except requests.RequestException as e:
                logger.error(f"HHI GET scan failed for {self.path}: {str(e)}")
                return self.findings
        
        # Test POST
        if self.method == 'POST' and self.post_body:
            try:
                data = {key: "test" for key in self.post_body}
                response = self.session.post(self.path, json=data, headers=headers, timeout=5)
                if response.status_code in [200, 301, 302] and malicious_host in response.text:
                    self.hhi_steps.append(f'POST {self.path} with Host: {malicious_host} and {json.dumps(data)}')
            except requests.RequestException as e:
                logger.error(f"HHI POST scan failed for {self.path}: {str(e)}")
                return self.findings

        if self.hhi_steps:
            finding = {
                'type': 'HOST Header Injection (HHI)',
                'severity': 'High',
                'description': 'The application is vulnerable to HOST Header Injection attacks. This vulnerability allows an attacker to inject malicious HOST headers, potentially leading to various security issues like cache poisoning or cross-site scripting.',
                'reproduce': '\n'.join(self.hhi_steps),
                'mitigation': 'Validate and sanitize the Host header'
            }
            self.findings.append(finding)
            print(f"[VULN] {finding['type']} - Severity: {finding['severity']}")
            print(f"  Description: {finding['description']}")
            print(f"  Steps to Reproduce:\n{finding['reproduce']}")
            print(f"  Mitigation: {finding['mitigation']}\n")
            logger.info(f"Found: HHI at {self.path}")

        return self.findings