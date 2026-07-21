#!/usr/bin/env python3
"""
Advanced Bulk HTTP Request Bomber / Load Tester
Version: 2.0
Author: Security Research Tool
License: Educational Purpose Only

Features:
- Multi-threaded request bombing
- Support for GET, POST, PUT, DELETE methods
- Custom headers and payloads
- Proxy support
- Rate limiting
- Response analysis
- Real-time statistics
- Export results
- Distributed attack simulation
- Various payload types (JSON, form data, multipart)
- Request delay randomization
- Session management
- Error handling
- Progress tracking
"""

import requests
import argparse
import sys
import os
import time
import json
import threading
import queue
import random
import string
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Optional, Any, Union
import logging
from collections import defaultdict, deque
import signal
import hashlib
import re

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Color:
    """ANSI color codes for terminal output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

class RequestStats:
    """Statistics collector for request metrics"""
    
    def __init__(self):
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.total_response_time = 0
        self.min_response_time = float('inf')
        self.max_response_time = 0
        self.status_codes = defaultdict(int)
        self.errors = defaultdict(int)
        self.bytes_received = 0
        self.bytes_sent = 0
        self.start_time = None
        self.lock = threading.Lock()
        
    def update(self, success: bool, response_time: float, status_code: int, 
               bytes_recv: int = 0, bytes_sent: int = 0, error: str = None):
        """Update statistics with request results"""
        with self.lock:
            self.total_requests += 1
            self.total_response_time += response_time
            
            if success:
                self.successful_requests += 1
            else:
                self.failed_requests += 1
                
            if status_code > 0:
                self.status_codes[status_code] += 1
                
            if error:
                self.errors[error] += 1
                
            self.bytes_received += bytes_recv
            self.bytes_sent += bytes_sent
            
            if response_time > 0:
                self.min_response_time = min(self.min_response_time, response_time)
                self.max_response_time = max(self.max_response_time, response_time)
                
    def get_stats(self) -> Dict:
        """Get current statistics"""
        with self.lock:
            avg_time = self.total_response_time / self.total_requests if self.total_requests > 0 else 0
            
            return {
                'total_requests': self.total_requests,
                'successful': self.successful_requests,
                'failed': self.failed_requests,
                'success_rate': (self.successful_requests / self.total_requests * 100) if self.total_requests > 0 else 0,
                'avg_response_time': avg_time,
                'min_response_time': self.min_response_time if self.min_response_time != float('inf') else 0,
                'max_response_time': self.max_response_time,
                'status_codes': dict(self.status_codes),
                'errors': dict(self.errors),
                'bytes_received': self.bytes_received,
                'bytes_sent': self.bytes_sent,
                'total_bandwidth': self.bytes_received + self.bytes_sent
            }

class BulkBomber:
    """Advanced Bulk HTTP Request Bomber"""
    
    def __init__(self, target_url: str, method: str = 'GET', headers: Dict = None,
                 payload: Union[Dict, str] = None, threads: int = 10,
                 total_requests: int = 100, timeout: int = 5,
                 proxy: str = None, user_agent: str = None,
                 verbose: bool = False, output_file: str = None,
                 rate_limit: float = 0.0, delay_range: Tuple[float, float] = None,
                 follow_redirects: bool = True, verify_ssl: bool = False,
                 keep_alive: bool = True, cookies: Dict = None,
                 auth: Tuple[str, str] = None, session_file: str = None):
        """
        Initialize the bulk bomber
        
        Args:
            target_url: Target URL
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            headers: Custom headers
            payload: Request payload
            threads: Number of concurrent threads
            total_requests: Total number of requests to send
            timeout: Request timeout in seconds
            proxy: Proxy URL
            user_agent: Custom User-Agent
            verbose: Enable verbose output
            output_file: File to save results
            rate_limit: Delay between requests (seconds)
            delay_range: Random delay range (min, max)
            follow_redirects: Follow redirects
            verify_ssl: Verify SSL certificates
            keep_alive: Use keep-alive connections
            cookies: Cookies to send
            auth: Basic authentication (username, password)
            session_file: File to save/load session
        """
        self.target_url = self._normalize_url(target_url)
        self.method = method.upper()
        self.headers = headers or {}
        self.payload = payload
        self.threads = min(threads, 100)  # Cap at 100
        self.total_requests = total_requests
        self.timeout = timeout
        self.proxy = proxy
        self.user_agent = user_agent or self._get_random_user_agent()
        self.verbose = verbose
        self.output_file = output_file
        self.rate_limit = rate_limit
        self.delay_range = delay_range
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl
        self.keep_alive = keep_alive
        self.cookies = cookies or {}
        self.auth = auth
        self.session_file = session_file
        
        # Initialize statistics
        self.stats = RequestStats()
        self.results = []
        self.stop_flag = threading.Event()
        self.lock = threading.Lock()
        
        # Setup session
        self.session = requests.Session()
        self._setup_session()
        
        # Setup logging
        self._setup_logging()
        
        # Print banner
        self._print_banner()
        
    def _setup_session(self):
        """Setup requests session"""
        self.session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive' if self.keep_alive else 'close'
        })
        
        # Add custom headers
        for key, value in self.headers.items():
            self.session.headers[key] = value
            
        # Add cookies
        if self.cookies:
            self.session.cookies.update(self.cookies)
            
        # Add authentication
        if self.auth:
            self.session.auth = self.auth
            
        # Setup proxy
        if self.proxy:
            self.session.proxies = {
                'http': self.proxy,
                'https': self.proxy
            }
            
        # Disable SSL verification if requested
        if not self.verify_ssl:
            self.session.verify = False
            
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
        return url
        
    def _get_random_user_agent(self) -> str:
        """Generate a random User-Agent"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1'
        ]
        return random.choice(user_agents)
        
    def _print_banner(self):
        """Print tool banner"""
        banner = f"""
{Color.CYAN}{Color.BOLD}
╔══════════════════════════════════════════════════════════════╗
║         Advanced Bulk HTTP Request Bomber / Load Tester     ║
║                    Version 2.0                              ║
╚══════════════════════════════════════════════════════════════╝
{Color.RESET}
{Color.YELLOW}[*] Target: {self.target_url}
[*] Method: {self.method}
[*] Total Requests: {self.total_requests:,}
[*] Threads: {self.threads}
[*] Timeout: {self.timeout}s
[*] Rate Limit: {self.rate_limit}s
[*] Delay Range: {self.delay_range if self.delay_range else 'None'}
[*] Proxy: {self.proxy if self.proxy else 'None'}
{Color.RESET}
        """
        print(banner)
        
    def _get_payload(self) -> Union[Dict, str, None]:
        """Prepare payload for request"""
        if not self.payload:
            return None
            
        if isinstance(self.payload, dict):
            # Generate dynamic payload values
            payload = self.payload.copy()
            for key, value in payload.items():
                if isinstance(value, str):
                    # Replace placeholders with random values
                    if '{random}' in value:
                        payload[key] = value.replace('{random}', ''.join(random.choices(string.ascii_lowercase + string.digits, k=10)))
                    elif '{timestamp}' in value:
                        payload[key] = value.replace('{timestamp}', str(int(time.time())))
                    elif '{uuid}' in value:
                        payload[key] = value.replace('{uuid}', self._generate_uuid())
            return payload
        elif isinstance(self.payload, str):
            # String payload with replacements
            payload = self.payload
            if '{random}' in payload:
                payload = payload.replace('{random}', ''.join(random.choices(string.ascii_lowercase + string.digits, k=10)))
            if '{timestamp}' in payload:
                payload = payload.replace('{timestamp}', str(int(time.time())))
            return payload
        return self.payload
        
    def _generate_uuid(self) -> str:
        """Generate a random UUID"""
        return ''.join(random.choices(string.hexdigits.lower(), k=8)) + '-' + \
               ''.join(random.choices(string.hexdigits.lower(), k=4)) + '-' + \
               ''.join(random.choices(string.hexdigits.lower(), k=4)) + '-' + \
               ''.join(random.choices(string.hexdigits.lower(), k=4)) + '-' + \
               ''.join(random.choices(string.hexdigits.lower(), k=12))
        
    def _send_request(self, request_id: int) -> Dict:
        """
        Send a single HTTP request
        
        Returns:
            Dict with request results
        """
        # Apply rate limiting
        if self.rate_limit > 0:
            time.sleep(self.rate_limit)
            
        # Add random delay
        if self.delay_range:
            delay = random.uniform(self.delay_range[0], self.delay_range[1])
            time.sleep(delay)
            
        # Prepare request parameters
        payload = self._get_payload()
        start_time = time.time()
        
        try:
            # Prepare request arguments
            kwargs = {
                'timeout': self.timeout,
                'allow_redirects': self.follow_redirects,
                'verify': self.verify_ssl
            }
            
            # Add payload based on method
            if self.method in ['POST', 'PUT', 'PATCH']:
                if isinstance(payload, dict):
                    # Check if JSON content type
                    if 'application/json' in self.session.headers.get('Content-Type', ''):
                        kwargs['json'] = payload
                    else:
                        kwargs['data'] = payload
                elif payload:
                    kwargs['data'] = payload
                    
            # Send request based on method
            if self.method == 'GET':
                response = self.session.get(self.target_url, **kwargs)
            elif self.method == 'POST':
                response = self.session.post(self.target_url, **kwargs)
            elif self.method == 'PUT':
                response = self.session.put(self.target_url, **kwargs)
            elif self.method == 'DELETE':
                response = self.session.delete(self.target_url, **kwargs)
            elif self.method == 'PATCH':
                response = self.session.patch(self.target_url, **kwargs)
            else:
                response = self.session.request(self.method, self.target_url, **kwargs)
                
            # Calculate response time
            response_time = time.time() - start_time
            
            # Determine success
            success = 200 <= response.status_code < 400
            
            # Get response size
            response_size = len(response.content)
            request_size = len(str(payload or '')) if payload else 0
            
            # Update statistics
            self.stats.update(
                success=success,
                response_time=response_time,
                status_code=response.status_code,
                bytes_recv=response_size,
                bytes_sent=request_size
            )
            
            result = {
                'request_id': request_id,
                'timestamp': datetime.now().isoformat(),
                'success': success,
                'status_code': response.status_code,
                'response_time': response_time,
                'response_size': response_size,
                'request_size': request_size,
                'headers': dict(response.headers),
                'url': response.url,
                'error': None
            }
            
            # Get response preview for analysis
            if success and self.verbose:
                result['response_preview'] = response.text[:200] + '...' if len(response.text) > 200 else response.text
                
            return result
            
        except requests.exceptions.Timeout:
            response_time = time.time() - start_time
            self.stats.update(False, response_time, 0, error='Timeout')
            return {
                'request_id': request_id,
                'timestamp': datetime.now().isoformat(),
                'success': False,
                'status_code': 0,
                'response_time': response_time,
                'error': 'Timeout'
            }
            
        except requests.exceptions.ConnectionError:
            response_time = time.time() - start_time
            self.stats.update(False, response_time, 0, error='ConnectionError')
            return {
                'request_id': request_id,
                'timestamp': datetime.now().isoformat(),
                'success': False,
                'status_code': 0,
                'response_time': response_time,
                'error': 'ConnectionError'
            }
            
        except Exception as e:
            response_time = time.time() - start_time
            error_msg = str(e)
            self.stats.update(False, response_time, 0, error=error_msg)
            return {
                'request_id': request_id,
                'timestamp': datetime.now().isoformat(),
                'success': False,
                'status_code': 0,
                'response_time': response_time,
                'error': error_msg
            }
            
    def _display_progress(self):
        """Display current progress"""
        stats = self.stats.get_stats()
        elapsed = time.time() - self.stats.start_time if self.stats.start_time else 0
        
        progress = f"""
{Color.CYAN}Progress Update:{Color.RESET}
  Requests: {stats['total_requests']:,} / {self.total_requests:,}
  Progress: {(stats['total_requests']/self.total_requests*100):.1f}%
  Success Rate: {stats['success_rate']:.1f}%
  Avg Response Time: {stats['avg_response_time']:.3f}s
  Min/Max: {stats['min_response_time']:.3f}s / {stats['max_response_time']:.3f}s
  Status Codes: {', '.join([f'{code}:{count}' for code, count in list(stats['status_codes'].items())[:5]])}
  Bandwidth: {self._format_bytes(stats['total_bandwidth'])}
  Speed: {stats['total_bandwidth']/elapsed/1024 if elapsed > 0 else 0:.1f} KB/s
  Elapsed: {self._format_time(elapsed)}
        """
        print(progress)
        
    def _format_time(self, seconds: float) -> str:
        """Format time in human-readable format"""
        if seconds < 0:
            return "Unknown"
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        seconds = int(seconds % 60)
        
        if hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"
            
    def _format_bytes(self, bytes_value: int) -> str:
        """Format bytes in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f} TB"
        
    def _worker(self, request_queue: queue.Queue):
        """Worker thread for sending requests"""
        while not self.stop_flag.is_set():
            try:
                request_id = request_queue.get(timeout=1)
            except queue.Empty:
                break
                
            result = self._send_request(request_id)
            
            with self.lock:
                self.results.append(result)
                
            # Log result
            if self.verbose:
                status = f"{Color.GREEN}✓{Color.RESET}" if result['success'] else f"{Color.RED}✗{Color.RESET}"
                status_code = result.get('status_code', 'ERR')
                response_time = result.get('response_time', 0)
                print(f"[{request_id:4d}] {status} {status_code} {response_time:.3f}s")
                
            request_queue.task_done()
            
    def run(self) -> List[Dict]:
        """
        Start the request bombing
        
        Returns:
            List of results
        """
        self.stats.start_time = time.time()
        
        print(f"{Color.GREEN}[*] Starting request bombing...{Color.RESET}")
        print(f"{Color.YELLOW}[!] Press Ctrl+C to stop gracefully{Color.RESET}")
        
        # Setup signal handler
        signal.signal(signal.SIGINT, self._signal_handler)
        
        # Create request queue
        request_queue = queue.Queue()
        for i in range(self.total_requests):
            request_queue.put(i + 1)
            
        # Start worker threads
        threads = []
        for _ in range(min(self.threads, request_queue.qsize())):
            t = threading.Thread(target=self._worker, args=(request_queue,))
            t.daemon = True
            t.start()
            threads.append(t)
            
        # Monitor progress
        last_display = time.time()
        try:
            while not self.stop_flag.is_set() and not request_queue.empty():
                time.sleep(1)
                
                # Display progress every 5 seconds
                if time.time() - last_display > 5:
                    self._display_progress()
                    last_display = time.time()
                    
        except KeyboardInterrupt:
            print(f"\n{Color.YELLOW}[!] Interrupted by user.{Color.RESET}")
            self.stop_flag.set()
            
        # Wait for threads to finish
        for t in threads:
            t.join(timeout=2)
            
        # Save results
        if self.output_file:
            self._save_results()
            
        # Display final results
        self._display_final_results()
        
        return self.results
        
    def _signal_handler(self, sig, frame):
        """Handle Ctrl+C gracefully"""
        print(f"\n{Color.YELLOW}[!] Received interrupt signal. Shutting down...{Color.RESET}")
        self.stop_flag.set()
        
    def _display_final_results(self):
        """Display final results summary"""
        elapsed = time.time() - self.stats.start_time
        stats = self.stats.get_stats()
        
        print(f"\n{Color.CYAN}{'='*60}")
        print(f"{Color.BOLD}FINAL RESULTS SUMMARY{Color.RESET}")
        print(f"{Color.CYAN}{'='*60}{Color.RESET}")
        
        print(f"{Color.WHITE}Target: {self.target_url}")
        print(f"Method: {self.method}")
        print(f"Total Requests: {stats['total_requests']:,}")
        print(f"Successful: {stats['successful']:,}")
        print(f"Failed: {stats['failed']:,}")
        print(f"Success Rate: {stats['success_rate']:.1f}%")
        print(f"Average Response Time: {stats['avg_response_time']:.3f}s")
        print(f"Min Response Time: {stats['min_response_time']:.3f}s")
        print(f"Max Response Time: {stats['max_response_time']:.3f}s")
        print(f"Total Bandwidth: {self._format_bytes(stats['total_bandwidth'])}")
        print(f"Average Speed: {(stats['total_bandwidth']/elapsed/1024) if elapsed > 0 else 0:.1f} KB/s")
        print(f"Time Elapsed: {self._format_time(elapsed)}{Color.RESET}")
        
        if stats['status_codes']:
            print(f"\n{Color.YELLOW}Status Code Distribution:{Color.RESET}")
            for code, count in sorted(stats['status_codes'].items()):
                percentage = (count / stats['total_requests'] * 100) if stats['total_requests'] > 0 else 0
                bar = '█' * int(percentage / 2)  # Simple progress bar
                print(f"  {code}: {count:,} ({percentage:.1f}%) {bar}")
                
        if stats['errors']:
            print(f"\n{Color.RED}Errors:{Color.RESET}")
            for error, count in sorted(stats['errors'].items(), key=lambda x: x[1], reverse=True):
                print(f"  {error}: {count:,}")
                
        if self.output_file:
            print(f"\n{Color.GREEN}[+] Results saved to: {self.output_file}{Color.RESET}")
            
        print(f"{Color.CYAN}{'='*60}{Color.RESET}")
        
    def _save_results(self):
        """Save results to file"""
        if not self.output_file:
            return
            
        try:
            data = {
                'target': self.target_url,
                'method': self.method,
                'timestamp': datetime.now().isoformat(),
                'total_requests': self.total_requests,
                'threads': self.threads,
                'timeout': self.timeout,
                'rate_limit': self.rate_limit,
                'statistics': self.stats.get_stats(),
                'results': self.results[:10] if len(self.results) > 10 else self.results  # Limit for size
            }
            
            with open(self.output_file, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Error saving results: {str(e)}")

def load_payload_file(filename: str) -> Union[Dict, str, None]:
    """Load payload from file"""
    try:
        if not os.path.exists(filename):
            return None
            
        with open(filename, 'r') as f:
            content = f.read().strip()
            
        # Try to parse as JSON
        try:
            return json.loads(content)
        except:
            return content
            
    except Exception as e:
        return None

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Advanced Bulk HTTP Request Bomber / Load Tester',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic GET request bombing
  python bulk_bomber.py https://example.com -t 50 -n 1000
  
  # POST request with JSON payload
  python bulk_bomber.py https://example.com/api --method POST --payload '{"key":"value"}' -t 20 -n 500
  
  # Load test with delay randomization
  python bulk_bomber.py https://example.com -t 30 -n 5000 --delay 0.1 0.5
  
  # With proxy and custom headers
  python bulk_bomber.py https://example.com -t 20 -n 200 -p http://127.0.0.1:8080 -H "Authorization: Bearer token"
  
  # Save results
  python bulk_bomber.py https://example.com -t 50 -n 1000 -v -o results.json
  
  # With cookies and authentication
  python bulk_bomber.py https://example.com --cookies '{"session":"123"}' --auth admin:password
        """
    )
    
    parser.add_argument('target', help='Target URL')
    parser.add_argument('--method', default='GET', help='HTTP method (GET, POST, PUT, DELETE, PATCH)')
    parser.add_argument('-n', '--total-requests', type=int, default=100, help='Total number of requests (default: 100)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=5, help='Request timeout in seconds (default: 5)')
    parser.add_argument('-p', '--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--user-agent', help='Custom User-Agent string')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-o', '--output', help='Output file for results (JSON format)')
    parser.add_argument('-r', '--rate-limit', type=float, default=0, help='Rate limit in seconds (default: 0)')
    parser.add_argument('--delay', nargs=2, type=float, help='Random delay range (min max) in seconds')
    parser.add_argument('--no-redirects', action='store_true', help='Disable following redirects')
    parser.add_argument('--verify-ssl', action='store_true', help='Verify SSL certificates')
    parser.add_argument('--no-keep-alive', action='store_true', help='Disable keep-alive connections')
    parser.add_argument('--payload', help='Payload for POST/PUT requests (JSON string or file)')
    parser.add_argument('--headers', '-H', action='append', help='Custom headers (e.g., "Header: Value")')
    parser.add_argument('--cookies', help='Cookies as JSON string')
    parser.add_argument('--auth', help='Basic authentication (username:password)')
    parser.add_argument('--session-file', help='File to save/load session')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.target:
        print(f"{Color.RED}[-] Error: Target URL is required{Color.RESET}")
        sys.exit(1)
        
    # Parse headers
    headers = {}
    if args.headers:
        for h in args.headers:
            if ':' in h:
                key, value = h.split(':', 1)
                headers[key.strip()] = value.strip()
                
    # Parse cookies
    cookies = {}
    if args.cookies:
        try:
            cookies = json.loads(args.cookies)
        except:
            print(f"{Color.RED}[-] Error: Invalid cookies JSON{Color.RESET}")
            sys.exit(1)
            
    # Parse authentication
    auth = None
    if args.auth:
        if ':' in args.auth:
            username, password = args.auth.split(':', 1)
            auth = (username, password)
        else:
            print(f"{Color.RED}[-] Error: Auth must be in format username:password{Color.RESET}")
            sys.exit(1)
            
    # Parse payload
    payload = None
    if args.payload:
        # Try to load from file
        if os.path.exists(args.payload):
            payload = load_payload_file(args.payload)
            if payload:
                print(f"{Color.GREEN}[+] Loaded payload from {args.payload}{Color.RESET}")
        else:
            # Try as JSON
            try:
                payload = json.loads(args.payload)
            except:
                payload = args.payload
                
    # Create and run the bomber
    try:
        bomber = BulkBomber(
            target_url=args.target,
            method=args.method,
            headers=headers,
            payload=payload,
            threads=args.threads,
            total_requests=args.total_requests,
            timeout=args.timeout,
            proxy=args.proxy,
            user_agent=args.user_agent,
            verbose=args.verbose,
            output_file=args.output,
            rate_limit=args.rate_limit,
            delay_range=(args.delay[0], args.delay[1]) if args.delay else None,
            follow_redirects=not args.no_redirects,
            verify_ssl=args.verify_ssl,
            keep_alive=not args.no_keep_alive,
            cookies=cookies,
            auth=auth,
            session_file=args.session_file
        )
        
        results = bomber.run()
        
        # Return appropriate exit code
        if results:
            sys.exit(0)
        else:
            sys.exit(1)
            
    except KeyboardInterrupt:
        print(f"\n{Color.YELLOW}[!] Interrupted by user{Color.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"{Color.RED}[-] Error: {str(e)}{Color.RESET}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()