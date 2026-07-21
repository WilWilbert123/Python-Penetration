#!/usr/bin/env python3
"""
Network discovery tool for identifying live hosts and open ports.
Enhanced with ARP scanning, ICMP, and TCP scanning capabilities.
"""

import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import sys
import ipaddress
import os
from threading import Lock
from datetime import datetime

try:
    from scapy.all import ARP, Ether, srp, IP, ICMP, sr1
except ImportError:
    print("Scapy not installed. Run: pip install scapy")
    sys.exit(1)

class NetworkDiscover:
    """Network discovery and scanning class"""
    
    def __init__(self, network, timeout=2, threads=50):
        self.network = network
        self.timeout = timeout
        self.threads = threads
        self.hosts = []
        self.open_ports = {}
        self.lock = Lock()
        self.start_time = None
        self.end_time = None
    
    def scan_arp(self):
        """Scan network using ARP requests"""
        print(f"[*] Scanning network: {self.network}")
        
        try:
            arp_request = ARP(pdst=self.network)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_request
            
            answered, unanswered = srp(packet, timeout=self.timeout, 
                                     verbose=False)
            
            self.hosts = []
            for sent, received in answered:
                self.hosts.append({
                    'ip': received.psrc,
                    'mac': received.hwsrc
                })
            
            return self.hosts
        except Exception as e:
            print(f"Error scanning network with ARP: {e}")
            return []
    
    def scan_icmp(self):
        """Scan network using ICMP echo requests"""
        hosts = []
        network = ipaddress.ip_network(self.network)
        
        def ping(ip):
            try:
                packet = IP(dst=str(ip)) / ICMP()
                response = sr1(packet, timeout=self.timeout, verbose=False)
                if response:
                    with self.lock:
                        hosts.append(str(ip))
            except Exception as e:
                pass
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(ping, network.hosts())
        
        return hosts
    
    def port_scan_single(self, ip, port):
        """Scan a single port on an IP address"""
        try:
            with socket.create_connection((ip, port), timeout=1):
                return port
        except (socket.timeout, socket.error, ConnectionRefusedError):
            return None
        except Exception:
            return None
    
    def port_scan(self, ip, ports=None):
        """Scan ports on a specific IP with parallel processing"""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 
                    445, 993, 995, 1433, 1521, 1723, 3306, 3389, 5432, 
                    5900, 6379, 8080]
        
        open_ports = []
        
        # Use ThreadPoolExecutor for parallel port scanning
        with ThreadPoolExecutor(max_workers=min(50, len(ports))) as executor:
            future_to_port = {
                executor.submit(self.port_scan_single, ip, port): port 
                for port in ports
            }
            
            for future in as_completed(future_to_port):
                result = future.result()
                if result is not None:
                    open_ports.append(result)
        
        return sorted(open_ports)
    
    def scan_ports(self, hosts=None):
        """Scan ports on multiple hosts"""
        if hosts is None:
            hosts = self.hosts
        
        for host in hosts:
            ip = host.get('ip', host)
            print(f"[*] Scanning ports on {ip}")
            open_ports = self.port_scan(ip)
            self.open_ports[ip] = open_ports
            
            if open_ports:
                print(f"[+] Open ports on {ip}: {open_ports}")
            else:
                print(f"[-] No open ports found on {ip}")
        
        return self.open_ports
    
    def get_os_info(self, ip):
        """Attempt OS detection using TTL"""
        try:
            packet = IP(dst=ip) / ICMP()
            response = sr1(packet, timeout=1, verbose=False)
            if response and IP in response:
                ttl = response[IP].ttl
                if ttl <= 64:
                    return "Linux/Unix"
                elif ttl <= 128:
                    return "Windows"
                else:
                    return "Unknown"
        except Exception as e:
            pass
        return "Unknown"
    
    def quick_scan(self):
        """Perform a quick scan without port scanning"""
        hosts = self.scan_arp()
        if not hosts:
            print("[-] No hosts found with ARP scan. Trying ICMP...")
            icmp_hosts = self.scan_icmp()
            if icmp_hosts:
                hosts = [{'ip': h, 'mac': 'N/A'} for h in icmp_hosts]
        
        return hosts
    
    def scan_network(self, include_os=True, skip_ports=False):
        """Full network scan"""
        self.start_time = datetime.now()
        print(f"[*] Starting network scan for {self.network}")
        print(f"[*] Started at: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 60)
        
        # Check for root privileges
        try:
            if os.geteuid() != 0:
                print("⚠️  Warning: Running without root privileges may limit scanning capabilities.")
                print("   Consider running with sudo for better results.\n")
        except AttributeError:
            # Windows doesn't have geteuid
            pass
        
        # ARP scan
        hosts = self.scan_arp()
        if not hosts:
            print("[-] No hosts found with ARP scan. Trying ICMP...")
            icmp_hosts = self.scan_icmp()
            if icmp_hosts:
                hosts = [{'ip': h, 'mac': 'N/A'} for h in icmp_hosts]
            else:
                print("[-] No hosts found with any scanning method.")
                return []
        
        print(f"[+] Found {len(hosts)} active hosts")
        
        # OS detection
        if include_os:
            print("\n[*] Performing OS detection...")
            for i, host in enumerate(hosts, 1):
                print(f"    [{i}/{len(hosts)}] Detecting OS for {host['ip']}")
                host['os'] = self.get_os_info(host['ip'])
        
        self.hosts = hosts
        
        # Port scan (if not skipped)
        if not skip_ports:
            print("\n[*] Starting port scan")
            self.scan_ports(hosts)
        else:
            print("\n[*] Skipping port scan (quick scan mode)")
        
        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()
        print(f"\n[*] Scan completed in {duration:.2f} seconds")
        
        return hosts
    
    def export_results(self, filename=None):
        """Export scan results to a file"""
        if filename is None:
            filename = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        try:
            with open(filename, 'w') as f:
                f.write("="*70 + "\n")
                f.write("NETWORK SCAN RESULTS\n")
                f.write("="*70 + "\n")
                f.write(f"Network: {self.network}\n")
                f.write(f"Scan started: {self.start_time}\n")
                f.write(f"Scan completed: {self.end_time}\n")
                f.write(f"Total hosts found: {len(self.hosts)}\n")
                f.write("-"*70 + "\n\n")
                
                for host in self.hosts:
                    ip = host.get('ip', '')
                    mac = host.get('mac', 'N/A')
                    os_name = host.get('os', 'Unknown')
                    ports = self.open_ports.get(ip, [])
                    
                    f.write(f"IP Address: {ip}\n")
                    f.write(f"MAC Address: {mac}\n")
                    f.write(f"OS: {os_name}\n")
                    if ports:
                        f.write(f"Open Ports: {', '.join(str(p) for p in ports)}\n")
                    else:
                        f.write("Open Ports: None\n")
                    f.write("-"*40 + "\n")
            
            print(f"[+] Results exported to: {filename}")
            return True
        except Exception as e:
            print(f"[-] Failed to export results: {e}")
            return False

def main():
    parser = argparse.ArgumentParser(
        description='Network discovery tool for identifying live hosts and open ports.',
        epilog='Example: python network_scanner.py -t 192.168.1.0/24 -p 22,80,443'
    )
    
    parser.add_argument('-t', '--target', required=True, 
                       help='Target network (e.g., 192.168.1.0/24)')
    parser.add_argument('-p', '--ports', 
                       help='Ports to scan (e.g., 22,80,443)')
    parser.add_argument('-T', '--timeout', type=int, default=2,
                       help='Timeout in seconds (default: 2)')
    parser.add_argument('-c', '--count', type=int, default=50,
                       help='Number of threads (default: 50)')
    parser.add_argument('--no-os', action='store_true',
                       help='Skip OS detection')
    parser.add_argument('--quick', action='store_true',
                       help='Quick scan (skip port scanning)')
    parser.add_argument('-o', '--output', 
                       help='Export results to file')
    parser.add_argument('--no-arp', action='store_true',
                       help='Skip ARP scan, use ICMP only')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    # Validate target network
    try:
        ipaddress.ip_network(args.target)
    except ValueError as e:
        print(f"Error: Invalid network format '{args.target}'. Use format like 192.168.1.0/24")
        sys.exit(1)
    
    # Parse ports
    ports = None
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(',')]
            if not all(1 <= p <= 65535 for p in ports):
                print("Error: Ports must be between 1 and 65535")
                sys.exit(1)
        except ValueError:
            print("Error: Invalid port specification. Use comma-separated numbers.")
            sys.exit(1)
    
    # Create scanner instance
    scanner = NetworkDiscover(args.target, args.timeout, args.count)
    
    # Perform scan
    try:
        hosts = scanner.scan_network(
            include_os=not args.no_os,
            skip_ports=args.quick
        )
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Scan failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    
    if not hosts:
        print("\n[-] No active hosts found.")
        sys.exit(0)
    
    # Display results
    print("\n" + "="*70)
    print("SCAN RESULTS")
    print("="*70)
    
    # Header
    print(f"{'IP Address':<20} {'MAC Address':<20} {'OS':<15} {'Ports'}")
    print("-"*70)
    
    # Results
    for host in hosts:
        ip = host.get('ip', '')
        mac = host.get('mac', 'N/A')
        os_name = host.get('os', 'Unknown')
        ports = scanner.open_ports.get(ip, [])
        
        if ports:
            port_str = ', '.join(str(p) for p in ports[:5])
            if len(ports) > 5:
                port_str += f", +{len(ports)-5} more"
        else:
            port_str = "None"
        
        print(f"{ip:<20} {mac:<20} {os_name:<15} {port_str}")
    
    print("="*70)
    print(f"Total hosts: {len(hosts)}")
    
    # Export results if requested
    if args.output:
        scanner.export_results(args.output)
    elif not args.quick and len(hosts) > 0:
        # Ask user if they want to export results
        try:
            response = input("\nExport results to file? (y/n): ").strip().lower()
            if response == 'y' or response == 'yes':
                scanner.export_results()
        except KeyboardInterrupt:
            print("\n")
            pass

if __name__ == "__main__":
    main()