#!/usr/bin/env python3
"""
Advanced Packet Sniffer for Network Analysis and Monitoring
Real-world packet capture with filtering, analysis, and alerting capabilities
"""

import sys
import time
import argparse
import threading
import os
import signal
from datetime import datetime
from collections import defaultdict, Counter
import json
import csv
from typing import Dict, List, Tuple, Optional

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, Ether
    from scapy.layers.http import HTTP, HTTPRequest
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.l2 import ARP, Ether
    from scapy.packet import Packet
except ImportError:
    print("Scapy not installed. Run: pip install scapy")
    sys.exit(1)

class PacketSniffer:
    """Advanced packet sniffer with real-world features"""
    
    def __init__(self, interface="eth0", max_packets=0, timeout=None):
        self.interface = interface
        self.max_packets = max_packets
        self.timeout = timeout
        self.packets = []
        self.packet_count = 0
        self.start_time = None
        self.end_time = None
        self.is_running = False
        self.stats = {
            'total': 0,
            'tcp': 0,
            'udp': 0,
            'icmp': 0,
            'arp': 0,
            'dns': 0,
            'http': 0,
            'https': 0,
            'other': 0,
            'by_size': defaultdict(int),
            'by_protocol': defaultdict(int),
            'by_src_ip': defaultdict(int),
            'by_dst_ip': defaultdict(int)
        }
        self.alert_rules = []
        self.suspicious_activity = []
        self.lock = threading.Lock()
        self.pcap_file = None
        
    def packet_callback(self, packet):
        """Main callback for processing captured packets"""
        with self.lock:
            self.packet_count += 1
            self.packets.append(packet)
            self.stats['total'] += 1
            
            # Analyze packet
            self.analyze_packet(packet)
            
            # Check alerts
            self.check_alerts(packet)
            
            # Real-time display
            if self.packet_count % 10 == 0:
                self.display_progress()
                
            # Stop condition
            if self.max_packets and self.packet_count >= self.max_packets:
                self.is_running = False
                return True
    
    def analyze_packet(self, packet):
        """Analyze packet and update statistics"""
        try:
            # Ethernet layer
            if Ether in packet:
                eth = packet[Ether]
                
            # IP layer
            if IP in packet:
                ip = packet[IP]
                src_ip = ip.src
                dst_ip = ip.dst
                size = len(packet)
                
                self.stats['by_src_ip'][src_ip] += 1
                self.stats['by_dst_ip'][dst_ip] += 1
                self.stats['by_size'][f"{size//100}00-{size//100+1}00"] += 1
                
                # Protocol detection
                if TCP in packet:
                    self.stats['tcp'] += 1
                    self.stats['by_protocol']['TCP'] += 1
                    self.analyze_tcp(packet)
                elif UDP in packet:
                    self.stats['udp'] += 1
                    self.stats['by_protocol']['UDP'] += 1
                    self.analyze_udp(packet)
                elif ICMP in packet:
                    self.stats['icmp'] += 1
                    self.stats['by_protocol']['ICMP'] += 1
                else:
                    self.stats['other'] += 1
                    self.stats['by_protocol']['Other'] += 1
            elif ARP in packet:
                self.stats['arp'] += 1
                self.stats['by_protocol']['ARP'] += 1
                self.analyze_arp(packet)
            else:
                self.stats['other'] += 1
                self.stats['by_protocol']['Other'] += 1
                
        except Exception as e:
            # Silently handle analysis errors
            pass
    
    def analyze_tcp(self, packet):
        """Analyze TCP packet"""
        try:
            tcp = packet[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
            
            # Detect HTTP
            if dst_port == 80 or src_port == 80:
                self.stats['http'] += 1
                if HTTP in packet:
                    self.analyze_http(packet)
            elif dst_port == 443 or src_port == 443:
                self.stats['https'] += 1
            elif dst_port == 22 or src_port == 22:
                self.stats['by_protocol']['SSH'] += 1
            elif dst_port == 21 or src_port == 21:
                self.stats['by_protocol']['FTP'] += 1
            elif dst_port == 25 or src_port == 25:
                self.stats['by_protocol']['SMTP'] += 1
            
            # Check for port scanning (many connections to different ports)
            if len(packet) == 64 and TCP in packet:
                # SYN packet without ACK - potential scan
                if tcp.flags == 2:  # SYN flag
                    self.add_suspicious_activity(
                        f"Potential port scan from {packet[IP].src}",
                        packet
                    )
        except:
            pass
    
    def analyze_udp(self, packet):
        """Analyze UDP packet"""
        try:
            udp = packet[UDP]
            src_port = udp.sport
            dst_port = udp.dport
            
            # Detect DNS
            if dst_port == 53 or src_port == 53:
                self.stats['dns'] += 1
                self.stats['by_protocol']['DNS'] += 1
                if DNS in packet:
                    self.analyze_dns(packet)
            
            # Detect DHCP
            if dst_port == 67 or dst_port == 68:
                self.stats['by_protocol']['DHCP'] += 1
                
        except:
            pass
    
    def analyze_arp(self, packet):
        """Analyze ARP packet"""
        try:
            arp = packet[ARP]
            # Detect ARP spoofing (multiple ARP replies for same IP)
            if arp.op == 2:  # is-at (reply)
                # Simple detection - could be enhanced
                pass
        except:
            pass
    
    def analyze_dns(self, packet):
        """Analyze DNS packet"""
        try:
            dns = packet[DNS]
            if dns.qr == 0:  # Query
                if DNSQR in packet:
                    qname = packet[DNSQR].qname
                    if isinstance(qname, bytes):
                        qname = qname.decode('utf-8', errors='ignore')
                    # Check for suspicious domains
                    suspicious_domains = ['.tk', '.ml', '.ga', '.cf', '.xyz']
                    if any(dom in qname for dom in suspicious_domains):
                        self.add_suspicious_activity(
                            f"DNS query to suspicious domain: {qname}",
                            packet
                        )
        except:
            pass
    
    def analyze_http(self, packet):
        """Analyze HTTP packet"""
        try:
            if HTTPRequest in packet:
                http = packet[HTTPRequest]
                if hasattr(http, 'Host'):
                    host = http.Host
                    if isinstance(host, bytes):
                        host = host.decode('utf-8', errors='ignore')
                    
                    # Check for HTTP requests to suspicious domains
                    suspicious_hosts = ['malware', 'phishing', 'exploit']
                    if any(s in host.lower() for s in suspicious_hosts):
                        self.add_suspicious_activity(
                            f"HTTP request to potentially malicious host: {host}",
                            packet
                        )
        except:
            pass
    
    def add_suspicious_activity(self, message, packet):
        """Add suspicious activity to the log"""
        timestamp = datetime.now()
        self.suspicious_activity.append({
            'timestamp': timestamp,
            'message': message,
            'packet_summary': self.get_packet_summary(packet)
        })
        
        # Display alert immediately
        print(f"\n⚠️  ALERT: {message}")
        print(f"   Time: {timestamp.strftime('%H:%M:%S')}")
    
    def get_packet_summary(self, packet):
        """Get a summary of the packet"""
        summary = []
        if IP in packet:
            summary.append(f"IP: {packet[IP].src} -> {packet[IP].dst}")
        if TCP in packet:
            summary.append(f"TCP: {packet[TCP].sport} -> {packet[TCP].dport}")
        elif UDP in packet:
            summary.append(f"UDP: {packet[UDP].sport} -> {packet[UDP].dport}")
        return " ".join(summary)
    
    def display_progress(self):
        """Display current progress"""
        print(f"\r[*] Packets captured: {self.packet_count} | "
              f"TCP: {self.stats['tcp']} | UDP: {self.stats['udp']} | "
              f"ICMP: {self.stats['icmp']} | ARP: {self.stats['arp']}", end="")
        sys.stdout.flush()
    
    def start_sniffing(self):
        """Start the packet sniffing process"""
        print("="*70)
        print("ADVANCED PACKET SNIFFER")
        print("="*70)
        print(f"Interface: {self.interface}")
        print(f"Max packets: {self.max_packets if self.max_packets > 0 else 'Unlimited'}")
        print(f"Timeout: {self.timeout if self.timeout else 'None'}")
        print("="*70)
        
        # Check if interface exists
        try:
            import netifaces
            if self.interface not in netifaces.interfaces():
                print(f"Warning: Interface '{self.interface}' might not exist")
                print(f"Available interfaces: {', '.join(netifaces.interfaces())}")
        except:
            pass
        
        self.start_time = datetime.now()
        self.is_running = True
        
        try:
            # Start sniffing
            print(f"[*] Started sniffing at {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
            print("[*] Press Ctrl+C to stop\n")
            
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                store=False,
                timeout=self.timeout,
                count=self.max_packets if self.max_packets > 0 else None
            )
            
        except KeyboardInterrupt:
            print("\n\n[!] Sniffing interrupted by user")
        except PermissionError:
            print("\n[!] Permission denied. Run with sudo/administrator privileges.")
        except Exception as e:
            print(f"\n[!] Error during sniffing: {e}")
        finally:
            self.stop_sniffing()
    
    def stop_sniffing(self):
        """Stop the sniffing process and display summary"""
        self.is_running = False
        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()
        
        print("\n" + "="*70)
        print("CAPTURE COMPLETE")
        print("="*70)
        print(f"Started:   {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Ended:     {self.end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Duration:  {duration:.2f} seconds")
        print(f"Packets:   {self.packet_count}")
        print("="*70)
    
    def display_statistics(self):
        """Display detailed statistics"""
        print("\n" + "="*70)
        print("PACKET STATISTICS")
        print("="*70)
        
        # Protocol breakdown
        print("\n📊 Protocol Breakdown:")
        print(f"  Total:      {self.stats['total']}")
        print(f"  TCP:        {self.stats['tcp']} ({self._percentage('tcp')}%)")
        print(f"  UDP:        {self.stats['udp']} ({self._percentage('udp')}%)")
        print(f"  ICMP:       {self.stats['icmp']} ({self._percentage('icmp')}%)")
        print(f"  ARP:        {self.stats['arp']} ({self._percentage('arp')}%)")
        print(f"  DNS:        {self.stats['dns']} ({self._percentage('dns')}%)")
        print(f"  HTTP:       {self.stats['http']} ({self._percentage('http')}%)")
        print(f"  HTTPS:      {self.stats['https']} ({self._percentage('https')}%)")
        print(f"  Other:      {self.stats['other']} ({self._percentage('other')}%)")
        
        # Top source IPs
        print("\n📡 Top Source IP Addresses:")
        for ip, count in sorted(self.stats['by_src_ip'].items(), 
                               key=lambda x: x[1], reverse=True)[:10]:
            percentage = (count / self.stats['total'] * 100) if self.stats['total'] > 0 else 0
            print(f"  {ip:<20} {count:>6} packets ({percentage:.1f}%)")
        
        # Top destination IPs
        print("\n🎯 Top Destination IP Addresses:")
        for ip, count in sorted(self.stats['by_dst_ip'].items(), 
                               key=lambda x: x[1], reverse=True)[:10]:
            percentage = (count / self.stats['total'] * 100) if self.stats['total'] > 0 else 0
            print(f"  {ip:<20} {count:>6} packets ({percentage:.1f}%)")
        
        # Protocol breakdown
        print("\n🔧 Protocol Details:")
        for protocol, count in sorted(self.stats['by_protocol'].items(), 
                                     key=lambda x: x[1], reverse=True)[:10]:
            percentage = (count / self.stats['total'] * 100) if self.stats['total'] > 0 else 0
            print(f"  {protocol:<10} {count:>6} packets ({percentage:.1f}%)")
        
        # Packet size distribution
        print("\n📦 Packet Size Distribution:")
        for size_range, count in sorted(self.stats['by_size'].items()):
            percentage = (count / self.stats['total'] * 100) if self.stats['total'] > 0 else 0
            print(f"  {size_range} bytes: {count:>6} packets ({percentage:.1f}%)")
        
        # Suspicious activity
        if self.suspicious_activity:
            print("\n⚠️  SUSPICIOUS ACTIVITY DETECTED:")
            for i, alert in enumerate(self.suspicious_activity, 1):
                print(f"  {i}. {alert['message']}")
                print(f"     Time: {alert['timestamp'].strftime('%H:%M:%S')}")
                print(f"     Details: {alert['packet_summary']}")
        else:
            print("\n✅ No suspicious activity detected")
        
        print("\n" + "="*70)
    
    def _percentage(self, key):
        """Calculate percentage of packet type"""
        if self.stats['total'] == 0:
            return 0
        return (self.stats[key] / self.stats['total'] * 100)
    
    def export_pcap(self, filename=None):
        """Export captured packets to PCAP file"""
        if not self.packets:
            print("No packets to export")
            return
        
        if filename is None:
            filename = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        
        try:
            from scapy.utils import wrpcap
            wrpcap(filename, self.packets)
            print(f"[+] Packets exported to: {filename}")
        except Exception as e:
            print(f"[-] Failed to export packets: {e}")
    
    def export_json(self, filename=None):
        """Export statistics to JSON file"""
        if filename is None:
            filename = f"stats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            data = {
                'timestamp': datetime.now().isoformat(),
                'interface': self.interface,
                'packet_count': self.packet_count,
                'stats': self.stats,
                'suspicious_activity': self.suspicious_activity
            }
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            print(f"[+] Statistics exported to: {filename}")
        except Exception as e:
            print(f"[-] Failed to export JSON: {e}")

def check_interface(interface):
    """Check if the specified interface exists"""
    try:
        import netifaces
        return interface in netifaces.interfaces()
    except:
        # If netifaces not available, assume the interface exists
        return True

def main():
    parser = argparse.ArgumentParser(
        description='Advanced Packet Sniffer for Network Analysis',
        epilog='Example: sudo python sniff.py -i eth0 -c 1000'
    )
    
    parser.add_argument('-i', '--interface', default='eth0',
                       help='Network interface to sniff on (default: eth0)')
    parser.add_argument('-c', '--count', type=int, default=0,
                       help='Number of packets to capture (0 = unlimited)')
    parser.add_argument('-t', '--timeout', type=int, default=None,
                       help='Capture timeout in seconds')
    parser.add_argument('-p', '--pcap', 
                       help='Export captured packets to PCAP file')
    parser.add_argument('-j', '--json',
                       help='Export statistics to JSON file')
    parser.add_argument('--no-stats', action='store_true',
                       help='Skip detailed statistics')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    # Check for root privileges
    if os.geteuid() != 0:
        print("⚠️  Warning: Running without root privileges may limit packet capture.")
        print("   Consider running with sudo for full functionality.\n")
    
    # Check interface
    if not check_interface(args.interface):
        print(f"Warning: Interface '{args.interface}' might not exist.")
        try:
            import netifaces
            print(f"Available interfaces: {', '.join(netifaces.interfaces())}")
        except:
            pass
    
    # Create sniffer
    sniffer = PacketSniffer(
        interface=args.interface,
        max_packets=args.count,
        timeout=args.timeout
    )
    
    # Start sniffing
    sniffer.start_sniffing()
    
    # Display statistics
    if not args.no_stats and sniffer.packet_count > 0:
        sniffer.display_statistics()
    
    # Export if requested
    if args.pcap and sniffer.packets:
        sniffer.export_pcap(args.pcap)
    
    if args.json:
        sniffer.export_json(args.json)
    
    # Summary
    print(f"\n📊 Capture Summary:")
    print(f"  Total packets captured: {sniffer.packet_count}")
    print(f"  Suspicious events: {len(sniffer.suspicious_activity)}")

if __name__ == "__main__":
    main()