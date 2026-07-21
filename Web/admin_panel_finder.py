#!/usr/bin/env python3
"""
Advanced Admin Panel Finder - A comprehensive web admin panel discovery tool
Version: 2.0
Author: Security Research Tool
License: Educational Purpose Only
"""

import requests
import argparse
import sys
import os
import time
import json
import threading
import queue
from datetime import datetime
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import random
from typing import List, Dict, Tuple, Optional
import logging

# Disable SSL warnings for testing purposes
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class AdminPanelFinder:
    """Advanced Admin Panel Finder with multiple detection methods"""
    
    def __init__(self, target_url: str, threads: int = 20, timeout: int = 5,
                 user_agent: str = None, proxy: str = None, verbose: bool = False,
                 output_file: str = None, rate_limit: float = 0.1):
        """
        Initialize the Admin Panel Finder
        
        Args:
            target_url: Target URL to scan
            threads: Number of concurrent threads
            timeout: Request timeout in seconds
            user_agent: Custom User-Agent string
            proxy: Proxy URL (e.g., http://127.0.0.1:8080)
            verbose: Enable verbose output
            output_file: File to save results
            rate_limit: Delay between requests (seconds)
        """
        self.target_url = self._normalize_url(target_url)
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.output_file = output_file
        self.rate_limit = rate_limit
        self.session = requests.Session()
        self.results = []
        self.found_panels = []
        self.lock = threading.Lock()
        
        # Setup session
        self.session.headers.update({
            'User-Agent': user_agent or self._get_random_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        if proxy:
            self.session.proxies = {
                'http': proxy,
                'https': proxy
            }
        
        # Setup logging
        self._setup_logging()
        
        # Load wordlists
        self.admin_paths = self._load_wordlists()
        self.extensions = ['', '/', '.php', '.html', '.asp', '.aspx', '.jsp', '.do', '.action', '.cgi']
        
        # Detection indicators
        self.admin_indicators = [
            'dashboard', 'admin', 'panel', 'login', 'signin', 'log-in',
            'administrator', 'management', 'control', 'console', 'backend',
            'superuser', 'root', 'sysadmin', 'webadmin', 'siteadmin'
        ]
        
        self.response_indicators = [
            'admin', 'login', 'signin', 'password', 'username', 'auth',
            'dashboard', 'panel', 'control', 'manage', 'session', 'welcome'
        ]
        
        self.response_code_indicators = [200, 403, 401, 302]
        
        print(f"[*] Initializing Admin Panel Finder for: {self.target_url}")
        print(f"[*] Using {threads} threads, timeout: {timeout}s")
        print(f"[*] Loaded {len(self.admin_paths)} admin paths to test")
        
    def _setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO if self.verbose else logging.WARNING,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
    def _normalize_url(self, url: str) -> str:
        """Normalize URL format"""
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        if not url.endswith('/'):
            url += '/'
        return url
        
    def _get_random_user_agent(self) -> str:
        """Generate a random User-Agent"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        ]
        return random.choice(user_agents)
        
    def _load_wordlists(self) -> List[str]:
        """Load admin panel wordlists from various sources"""
        wordlists = []
        
        # Common admin paths
        common_paths = [
            'admin', 'administrator', 'adminpanel', 'admin-panel', 'admin_login',
            'dashboard', 'controlpanel', 'cpanel', 'panel', 'backend',
            'login', 'log-in', 'signin', 'sign-in', 'auth', 'authenticate',
            'user', 'users', 'account', 'accounts', 'profile', 'profiles',
            'manage', 'manager', 'management', 'administration', 'sysadmin',
            'root', 'superuser', 'super-admin', 'superadmin', 'webadmin',
            'siteadmin', 'wp-admin', 'wp-login', 'administrator-login',
            'admin-area', 'adminarea', 'admin-console', 'adminconsole',
            'operator', 'staff', 'employee', 'hr', 'finance', 'reports',
            'statistics', 'analytics', 'monitor', 'monitoring',
            'setting', 'settings', 'configuration', 'config',
            'system', 'system-admin', 'sys-admin'
        ]
        
        # Add common CMS admin paths
        cms_paths = [
            'wp-admin', 'wp-login', 'administrator', 'index.php/admin',
            'admin.php', 'login.php', 'admin/index.php', 'admin/login.php',
            'administrator/index.php', 'administrator/login.php',
            'cpanel', 'cpanel/login', 'whm', 'whm/login',
            'phpmyadmin', 'pma', 'mysql', 'myadmin',
            'webmail', 'mail', 'webmail/login',
            'plesk', 'plesk/login', 'webmin', 'webmin/login'
        ]
        
        # Security/authentication paths
        security_paths = [
            'auth', 'authenticate', 'login', 'logon', 'signin',
            'sso', 'sso/login', 'oauth', 'oauth/login',
            'ldap', 'ldap/login', 'adfs', 'adfs/login'
        ]
        
        wordlists.extend(common_paths)
        wordlists.extend(cms_paths)
        wordlists.extend(security_paths)
        
        # Remove duplicates while preserving order
        return list(dict.fromkeys(wordlists))
        
    def _check_path(self, path: str) -> Optional[Dict]:
        """Check if a path is an admin panel"""
        for extension in self.extensions:
            test_path = path + extension
            full_url = urljoin(self.target_url, test_path)
            
            try:
                # Implement rate limiting
                time.sleep(self.rate_limit)
                
                response = self.session.get(
                    full_url,
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=False
                )
                
                # Check if this looks like an admin panel
                if self._is_admin_panel(response, full_url):
                    return {
                        'url': full_url,
                        'status_code': response.status_code,
                        'title': self._extract_title(response.text),
                        'content_length': len(response.text),
                        'found_via': 'path_discovery',
                        'response_time': response.elapsed.total_seconds()
                    }
                
                # Check for interesting status codes
                if response.status_code in [401, 403]:
                    if self.verbose:
                        print(f"[+] Found protected path: {full_url} (Status: {response.status_code})")
                    return {
                        'url': full_url,
                        'status_code': response.status_code,
                        'found_via': 'protected_path'
                    }
                    
            except requests.exceptions.Timeout:
                pass
            except requests.exceptions.ConnectionError:
                pass
            except Exception as e:
                if self.verbose:
                    self.logger.debug(f"Error checking {full_url}: {str(e)}")
                    
        return None
        
    def _is_admin_panel(self, response: requests.Response, url: str) -> bool:
        """Check if a response indicates an admin panel"""
        # Check status code
        if response.status_code == 404:
            return False
            
        # Check for admin indicators in URL
        url_lower = url.lower()
        if any(indicator in url_lower for indicator in self.admin_indicators):
            # Check for login forms or admin content
            try:
                html_content = response.text.lower()
                
                # Check for login forms
                login_indicators = [
                    'login', 'sign in', 'sign-in', 'log in', 'password',
                    'username', 'email', 'user name', 'welcome',
                    'dashboard', 'admin panel', 'administrator'
                ]
                
                if any(indicator in html_content for indicator in login_indicators):
                    return True
                    
                # Check for form elements
                if '<form' in html_content:
                    if 'password' in html_content or 'login' in html_content:
                        return True
                        
                # Check for admin panel titles
                title = self._extract_title(response.text)
                if title:
                    title_lower = title.lower()
                    admin_titles = ['admin', 'login', 'dashboard', 'panel', 'control']
                    if any(admin in title_lower for admin in admin_titles):
                        return True
                        
            except:
                pass
                
        return False
        
    def _extract_title(self, html: str) -> str:
        """Extract page title from HTML"""
        try:
            match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
            if match:
                return match.group(1).strip()
        except:
            pass
        return ""
        
    def _analyze_robots_txt(self) -> List[str]:
        """Analyze robots.txt for admin paths"""
        found_paths = []
        try:
            robots_url = urljoin(self.target_url, 'robots.txt')
            response = self.session.get(robots_url, timeout=self.timeout, verify=False)
            
            if response.status_code == 200:
                for line in response.text.split('\n'):
                    if 'disallow' in line.lower() and 'admin' in line.lower():
                        # Extract path from Disallow
                        path_match = re.search(r'/[\w\-/]+', line)
                        if path_match:
                            path = path_match.group(0).lstrip('/')
                            found_paths.append(path)
                            
        except Exception as e:
            self.logger.debug(f"Error analyzing robots.txt: {str(e)}")
            
        return found_paths
        
    def _analyze_sitemap(self) -> List[str]:
        """Analyze sitemap.xml for admin paths"""
        found_paths = []
        try:
            sitemap_url = urljoin(self.target_url, 'sitemap.xml')
            response = self.session.get(sitemap_url, timeout=self.timeout, verify=False)
            
            if response.status_code == 200:
                # Find URLs in sitemap
                urls = re.findall(r'<loc>(.*?)</loc>', response.text, re.IGNORECASE)
                for url in urls:
                    if 'admin' in url.lower() or 'login' in url.lower():
                        path = url.replace(self.target_url, '').lstrip('/')
                        if path:
                            found_paths.append(path)
                            
        except Exception as e:
            self.logger.debug(f"Error analyzing sitemap: {str(e)}")
            
        return found_paths
        
    def _brute_force_search(self) -> None:
        """Perform brute force search for admin panels"""
        print(f"[*] Starting brute force scan with {self.threads} threads...")
        
        # Add paths found from robots.txt and sitemap
        extra_paths = []
        extra_paths.extend(self._analyze_robots_txt())
        extra_paths.extend(self._analyze_sitemap())
        
        # Combine all paths
        all_paths = list(set(self.admin_paths + extra_paths))
        
        # Create work queue
        work_queue = queue.Queue()
        for path in all_paths:
            work_queue.put(path)
            
        # Worker function
        def worker():
            while True:
                try:
                    path = work_queue.get(timeout=1)
                    result = self._check_path(path)
                    
                    if result and result.get('status_code') in self.response_code_indicators:
                        with self.lock:
                            self.results.append(result)
                            if result.get('title') or result.get('content_length'):
                                self.found_panels.append(result)
                                self._print_result(result)
                                
                    work_queue.task_done()
                    
                except queue.Empty:
                    break
                except Exception as e:
                    self.logger.debug(f"Worker error: {str(e)}")
                    work_queue.task_done()
                    
        # Start threads
        threads = []
        for _ in range(min(self.threads, work_queue.qsize())):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)
            
        # Wait for completion
        work_queue.join()
        for t in threads:
            t.join(timeout=1)
            
    def _print_result(self, result: Dict) -> None:
        """Print a discovered admin panel"""
        status = result.get('status_code', 'Unknown')
        url = result.get('url', 'Unknown')
        title = result.get('title', 'No Title')
        
        if status in [200, 401, 403]:
            print(f"[+] Found: {url} (Status: {status})")
            if title and title != 'No Title':
                print(f"    Title: {title}")
            if result.get('content_length'):
                print(f"    Content Length: {result['content_length']} bytes")
            print("-" * 50)
            
    def _scan_common_ports(self) -> None:
        """Scan for admin panels on common ports"""
        common_ports = [80, 443, 8080, 8443, 4443, 8000, 8008, 9000, 9090]
        
        print(f"[*] Scanning common ports for admin panels...")
        
        for port in common_ports:
            try:
                # Parse base URL
                parsed = urlparse(self.target_url)
                base_url = f"{parsed.scheme}://{parsed.netloc.split(':')[0]}:{port}"
                
                # Test common admin paths on this port
                test_paths = ['admin', 'login', 'dashboard', 'cpanel']
                for path in test_paths:
                    test_url = f"{base_url}/{path}"
                    try:
                        response = self.session.get(
                            test_url,
                            timeout=3,
                            allow_redirects=True,
                            verify=False
                        )
                        
                        if response.status_code in [200, 401, 403]:
                            print(f"[+] Found admin panel on port {port}: {test_url}")
                            self.results.append({
                                'url': test_url,
                                'status_code': response.status_code,
                                'found_via': 'port_scan'
                            })
                            
                    except:
                        pass
                        
            except:
                pass
                
    def run(self) -> None:
        """Main execution method"""
        start_time = time.time()
        
        print("\n" + "="*60)
        print(f"Admin Panel Finder - Starting Scan")
        print("="*60)
        print(f"Target: {self.target_url}")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-"*60)
        
        # Perform the scan
        self._brute_force_search()
        
        # Optional: Scan common ports
        if self.verbose:
            self._scan_common_ports()
            
        # Save results
        if self.output_file:
            self._save_results()
            
        # Print summary
        elapsed_time = time.time() - start_time
        self._print_summary(elapsed_time)
        
    def _print_summary(self, elapsed_time: float) -> None:
        """Print scan summary"""
        print("\n" + "="*60)
        print("Scan Summary")
        print("="*60)
        print(f"Total URLs tested: {len(self.admin_paths)}")
        print(f"Admin panels found: {len(self.found_panels)}")
        print(f"Protected/restricted: {len([r for r in self.results if r.get('status_code') in [401, 403]])}")
        print(f"Scan duration: {elapsed_time:.2f} seconds")
        
        if self.found_panels:
            print("\n[+] Admin panels discovered:")
            for panel in self.found_panels:
                print(f"  - {panel.get('url')} (Status: {panel.get('status_code')})")
        else:
            print("\n[-] No admin panels found.")
            
        if self.output_file:
            print(f"\n[+] Results saved to: {self.output_file}")
            
        print("="*60)
        
    def _save_results(self) -> None:
        """Save results to file"""
        try:
            # Prepare data for export
            export_data = {
                'scan_info': {
                    'target': self.target_url,
                    'timestamp': datetime.now().isoformat(),
                    'total_checked': len(self.admin_paths),
                    'found': len(self.found_panels)
                },
                'admin_panels': self.found_panels,
                'all_results': self.results
            }
            
            # Save as JSON
            with open(self.output_file, 'w') as f:
                json.dump(export_data, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Error saving results: {str(e)}")
            
    def get_results(self) -> List[Dict]:
        """Return scan results"""
        return self.found_panels

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Advanced Admin Panel Finder - Comprehensive web admin panel discovery tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python admin_panel_finder.py https://example.com
  python admin_panel_finder.py https://example.com -t 50 -v -o results.json
  python admin_panel_finder.py http://192.168.1.1 -p http://127.0.0.1:8080
        """
    )
    
    parser.add_argument('target', help='Target URL (e.g., https://example.com)')
    parser.add_argument('-t', '--threads', type=int, default=20,
                       help='Number of threads (default: 20)')
    parser.add_argument('--timeout', type=int, default=5,
                       help='Request timeout in seconds (default: 5)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('-p', '--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('-o', '--output', help='Output file for results (JSON format)')
    parser.add_argument('-r', '--rate-limit', type=float, default=0.1,
                       help='Request rate limit in seconds (default: 0.1)')
    parser.add_argument('--user-agent', help='Custom User-Agent string')
    
    args = parser.parse_args()
    
    # Validate target
    if not args.target:
        print("[-] Error: Target URL is required")
        sys.exit(1)
        
    try:
        # Create and run the scanner
        scanner = AdminPanelFinder(
            target_url=args.target,
            threads=args.threads,
            timeout=args.timeout,
            user_agent=args.user_agent,
            proxy=args.proxy,
            verbose=args.verbose,
            output_file=args.output,
            rate_limit=args.rate_limit
        )
        
        scanner.run()
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"[-] Error: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()