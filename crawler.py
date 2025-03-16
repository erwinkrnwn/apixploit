#!/usr/bin/env python3
import requests
import json
import logging
from urllib.parse import urljoin

# Configure logging
logging.basicConfig(
    filename='security_scan.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class OpenAPICrawler:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.openapi_path = '/api/openapi.json'
        self.session = requests.Session()
        self.endpoints = {}

    def fetch_openapi_spec(self):
        """Fetch OpenAPI specification from target"""
        spec_url = urljoin(self.target_url, self.openapi_path)
        try:
            response = self.session.get(spec_url)
            response.raise_for_status()
            logger.info(f"Successfully fetched OpenAPI spec from {spec_url}")
            return response.json()
        except requests.RequestException as e:
            logger.error(f"Failed to fetch OpenAPI spec: {str(e)}")
            return None

    def parse_openapi(self, spec):
        """Parse OpenAPI specification for endpoints, methods, and parameters"""
        if not spec or 'paths' not in spec:
            logger.error("Invalid or missing 'paths' in OpenAPI spec")
            return

        # Get base URL from servers
        base_path = spec.get('servers', [{}])[0].get('url', '')
        base_url = urljoin(self.target_url + '/', base_path.lstrip('/'))
        logger.info(f"Base URL determined: {base_url}")

        for path, methods in spec['paths'].items():
            full_path = urljoin(base_url + '/', path.lstrip('/'))  # Pastikan /api ada di full_path
            logger.debug(f"Processing path: {path}, Full path: {full_path}")
            for method, details in methods.items():
                endpoint_key = f"{full_path}_{method.upper()}"
                endpoint_info = {
                    'method': method.upper(),
                    'path': full_path,
                    'get_params': [],
                    'post_body': {}
                }

                # Parse GET parameters (default jika tidak ada)
                if 'parameters' in details:
                    for param in details['parameters']:
                        if param.get('in') == 'query':
                            endpoint_info['get_params'].append({
                                'name': param['name'],
                                'type': param.get('type', 'string'),
                                'required': param.get('required', False)
                            })
                elif method.upper() == 'GET':  # Tambahkan parameter default untuk GET
                    if 'sqli' in path:
                        endpoint_info['get_params'] = [{'name': 'username', 'type': 'string', 'required': True}]
                    elif 'xss' in path:
                        endpoint_info['get_params'] = [{'name': 'username', 'type': 'string', 'required': True}]
                    elif 'lfi' in path:
                        endpoint_info['get_params'] = [{'name': 'filename', 'type': 'string', 'required': True}]
                    elif 'rfi' in path:
                        endpoint_info['get_params'] = [{'name': 'imagelink', 'type': 'string', 'required': True}]
                    elif 'ssti' in path:
                        endpoint_info['get_params'] = [{'name': 'mathexp', 'type': 'string', 'required': True}]
                    elif 'hhi' in path:
                        endpoint_info['get_params'] = [{'name': 'email', 'type': 'string', 'required': True}]

                # Parse POST/PUT body
                if method.lower() in ['post', 'put'] and 'requestBody' in details:
                    content = details['requestBody'].get('content', {})
                    if 'application/json' in content:
                        schema_ref = content['application/json'].get('schema', {}).get('$ref', '')
                        if schema_ref:
                            schema_name = schema_ref.split('/')[-1]
                            schema = spec['components']['schemas'].get(schema_name, {})
                            if 'properties' in schema:
                                endpoint_info['post_body'] = {
                                    prop: {'type': details.get('type', 'string')}
                                    for prop, details in schema['properties'].items()
                                }

                self.endpoints[endpoint_key] = endpoint_info
                logger.debug(f"Added endpoint: {endpoint_key}")

    def crawl(self):
        """Run the crawling process"""
        logger.info(f"Crawling OpenAPI spec at {self.target_url}{self.openapi_path}")
        spec = self.fetch_openapi_spec()
        if spec:
            self.parse_openapi(spec)
            logger.info(f"Found {len(self.endpoints)} endpoints: {list(self.endpoints.keys())}")
            return self.endpoints
        logger.warning("No endpoints found due to failed crawl")
        return {}

    def save_endpoints(self, filename='endpoints.json'):
        """Save crawled endpoints to a JSON file"""
        with open(filename, 'w') as f:
            json.dump(self.endpoints, f, indent=4)
        logger.info(f"Endpoints saved to {filename}")

def main():
    parser = argparse.ArgumentParser(description='OpenAPI Crawler')
    parser.add_argument('--url', required=True, help='Target URL with OpenAPI spec')
    args = parser.parse_args()

    crawler = OpenAPICrawler(args.url)
    endpoints = crawler.crawl()
    crawler.save_endpoints()
    print(json.dumps(endpoints, indent=4))

if __name__ == "__main__":
    main()