import requests
import logging
import json
import html  # Tambahkan untuk escape HTML di langkah selanjutnya

logger = logging.getLogger(__name__)

class XSSScanner:
    def __init__(self, path, method, get_params, post_body):
        self.path = path
        self.method = method
        self.get_params = get_params
        self.post_body = post_body
        self.session = requests.Session()
        self.findings = []
        self.xss_steps = []

    def scan(self):
        payloads = ["<script>alert('xss')</script>", "'><img src=x onerror=alert(1)>"]
        
        # Test GET parameters
        for param in self.get_params:
            param_name = param['name']
            for payload in payloads:
                try:
                    if self.method == 'GET':
                        url = f"{self.path}?{param_name}={payload}"
                        response = self.session.get(url, timeout=5)
                        if response.status_code == 200 and payload in response.text:
                            self.xss_steps.append(f'GET {url}')
                except requests.RequestException as e:
                    logger.error(f"XSS GET scan failed for {url}: {str(e)}")
                    continue
        
        # Test POST body
        if self.method == 'POST' and self.post_body:
            for param_name in self.post_body:
                for payload in payloads:
                    try:
                        data = {param_name: payload}
                        response = self.session.post(self.path, json=data, timeout=5)
                        if response.status_code == 200 and payload in response.text:
                            self.xss_steps.append(f'POST {self.path} with {json.dumps(data)}')
                    except requests.RequestException as e:
                        logger.error(f"XSS POST scan failed for {self.path}: {str(e)}")
                        continue

        # Tambahkan finding jika ada langkah reproduksi
        if self.xss_steps:
            finding = {
                'type': 'Cross-Site Scripting (XSS)',
                'severity': 'High',
                'description': 'The application is susceptible to Cross-Site Scripting attacks. These vulnerabilities occur when unvalidated user inputs are rendered directly in the HTML page, allowing malicious scripts to be executed in the context of the website.',
                'reproduce': '\n'.join(self.xss_steps),
                'mitigation': 'Sanitize user input and implement Content Security Policy (CSP)'
            }
            self.findings.append(finding)
            print(f"[VULN] {finding['type']} - Severity: {finding['severity']}")
            print(f"  Description: {finding['description']}")
            print(f"  Steps to Reproduce:\n{finding['reproduce']}")
            print(f"  Mitigation: {finding['mitigation']}\n")
            logger.info(f"Found: XSS at {self.path}")

        return self.findings