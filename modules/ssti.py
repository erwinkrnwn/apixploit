import requests
import logging
import json
import html

logger = logging.getLogger(__name__)

class SSTIScanner:
    def __init__(self, path, method, get_params, post_body):
        self.path = path
        self.method = method
        self.get_params = get_params
        self.post_body = post_body
        self.session = requests.Session()
        self.findings = []
        self.ssti_steps = []

    def scan(self):
        payloads = ["{{7*7}}", "{# 7 * 7 #}"]
        
        # Test GET parameters
        for param in self.get_params:
            param_name = param['name']
            for payload in payloads:
                try:
                    if self.method == 'GET':
                        url = f"{self.path}?{param_name}={payload}"
                        response = self.session.get(url, timeout=5)
                        if response.status_code == 200 and "49" in response.text:
                            self.ssti_steps.append(f'GET {url}')
                except requests.RequestException as e:
                    logger.error(f"SSTI GET scan failed for {url}: {str(e)}")
                    continue
        
        # Test POST body
        if self.method == 'POST' and self.post_body:
            for param_name in self.post_body:
                for payload in payloads:
                    try:
                        data = {param_name: payload}
                        response = self.session.post(self.path, json=data, timeout=5)
                        if response.status_code == 200 and "49" in response.text:
                            self.ssti_steps.append(f'POST {self.path} with {json.dumps(data)}')
                    except requests.RequestException as e:
                        logger.error(f"SSTI POST scan failed for {self.path}: {str(e)}")
                        continue

        if self.ssti_steps:
            finding = {
                'type': 'Server-Side Template Injection (SSTI)',
                'severity': 'High',
                'description': 'The application is prone to Server-Side Template Injection attacks. SSTI occurs when user input is used directly in server-side templates, potentially leading to code execution on the server.',
                'reproduce': '\n'.join(self.ssti_steps),
                'mitigation': 'Sanitize user input and avoid dynamic template evaluation'
            }
            self.findings.append(finding)
            print(f"[VULN] {finding['type']} - Severity: {finding['severity']}")
            print(f"  Description: {finding['description']}")
            print(f"  Steps to Reproduce:\n{finding['reproduce']}")
            print(f"  Mitigation: {finding['mitigation']}\n")
            logger.info(f"Found: SSTI at {self.path}")

        return self.findings