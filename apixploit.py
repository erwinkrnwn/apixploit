#!/usr/bin/env python3
import argparse
import sys
import logging
import json
from crawler import OpenAPICrawler
from modules.passive import PassiveScanner
from modules.sqli import SQLInjectionScanner
from modules.broken_auth import BrokenAuthScanner
from modules.sensitive_data import SensitiveDataScanner
from modules.xxe import XXEScanner
from modules.broken_access import BrokenAccessScanner
from modules.misconfig import MisconfigScanner
from modules.xss import XSSScanner
from modules.deserialization import DeserializationScanner
from modules.components import ComponentsScanner
from modules.logging_monitoring import LoggingMonitoringScanner
from modules.hhi import HHIScanner
from modules.lfi import LFIScanner
from modules.rfi import RFIScanner
from modules.ssti import SSTIScanner
from modules.exploits import ExploitDemo
from modules.reporting import ReportGenerator

# Configure logging
logging.basicConfig(
    filename='security_scan.log',
    level=logging.INFO,  # Ubah dari DEBUG ke INFO
    format='%(asctime)s - %(levelname)s - %(message)s',
    force=True  # Paksa overwrite konfigurasi logging sebelumnya
)
logger = logging.getLogger(__name__)

class ApiXploit:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []
        self.endpoints = self.load_endpoints()

    def load_endpoints(self):
        logger.info(f"Loading endpoints for {self.target_url}")
        crawler = OpenAPICrawler(self.target_url)
        endpoints = crawler.crawl()
        if endpoints:
            crawler.save_endpoints()
            logger.info(f"Endpoints loaded: {list(endpoints.keys())}")
            return endpoints
        try:
            with open('endpoints.json', 'r') as f:
                endpoints = json.load(f)
                logger.info(f"Endpoints loaded from file: {list(endpoints.keys())}")
                return endpoints
        except FileNotFoundError:
            logger.error("No endpoints found and crawling failed.")
            return {}

    def run(self):
        logger.info(f"Starting scan on {self.target_url}")
        print(f"\nStarting scan on {self.target_url}...\n")
    
        # Passive Scanning
        logger.info("Running passive scan")
        passive = PassiveScanner(self.target_url)
        passive_results = passive.scan()
        self.vulnerabilities.extend(passive_results)
    
        # Active Scanning with endpoints from crawler
        logger.info(f"Starting active scan with {len(self.endpoints)} endpoints")
        for endpoint_key, info in self.endpoints.items():
            method = info['method']
            path = info['path']
            get_params = info['get_params']
            post_body = info['post_body']
            print(f"Scanning endpoint: {method} {path}")
            logger.info(f"Endpoint data - method: {method}, path: {path}, get_params: {get_params}, post_body: {post_body}")
            scanners = [
                SQLInjectionScanner(path, method, get_params, post_body),
                BrokenAuthScanner(path, method, get_params, post_body),
                SensitiveDataScanner(path, method, get_params, post_body),
                XXEScanner(path, method, get_params, post_body),
                BrokenAccessScanner(path, method, get_params, post_body),
                MisconfigScanner(path, method, get_params, post_body),
                XSSScanner(path, method, get_params, post_body),
                DeserializationScanner(path, method, get_params, post_body),
                ComponentsScanner(path, method, get_params, post_body),
                LoggingMonitoringScanner(path, method, get_params, post_body),
                HHIScanner(path, method, get_params, post_body),
                LFIScanner(self.target_url, path, method, get_params, post_body),  # Ubah di sini
                RFIScanner(path, method, get_params, post_body),
                SSTIScanner(path, method, get_params, post_body)
            ]
            for scanner in scanners:
                try:
                    logger.info(f"Running {scanner.__class__.__name__} on {method} {path}")
                    scan_results = scanner.scan()
                    logger.info(f"{scanner.__class__.__name__} results: {scan_results}")
                    if not isinstance(scan_results, list):
                        logger.error(f"Scanner {scanner.__class__.__name__} did not return a list: {scan_results}")
                        scan_results = []
                    for result in scan_results:
                        if not isinstance(result, dict) or 'type' not in result:
                            logger.error(f"Invalid result from {scanner.__class__.__name__}: {result}")
                        else:
                            self.vulnerabilities.append(result)
                except Exception as e:
                    logger.error(f"Error in {scanner.__class__.__name__} for {method} {path}: {str(e)}")
                    print(f"[ERROR] Scanner {scanner.__class__.__name__} failed: {str(e)}")
        
        # Exploit Demo
        print("\nRunning exploit demonstration...")
        logger.info("Running exploit demo")
        exploits = ExploitDemo(self.target_url)
        try:
            exploits.demo_sql_injection()
        except Exception as e:
            logger.error(f"Exploit demo failed: {str(e)}")
            print(f"[ERROR] Exploit demo failed: {str(e)}")
        
        # Generate HTML Report
        logger.info(f"Final vulnerabilities before report: {self.vulnerabilities}")
        reporter = ReportGenerator(self.target_url, self.vulnerabilities)
        try:
            reporter.generate_html()
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {str(e)}")
            print(f"[ERROR] Failed to generate HTML report: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description='ApiXploit - Advanced Security Scanner')
    parser.add_argument('--url', required=True, help='Target API URL')
    args = parser.parse_args()

    scanner = ApiXploit(args.url)
    try:
        scanner.run()
        logger.info("Scan completed successfully")
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        print(f"[ERROR] Scan failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()