#!/usr/bin/env python3
"""
macOS WiFi Network Scanner - Uses system_profiler (works on all macOS versions)
Real-world WiFi scanning with security assessment capabilities
"""

import sys
import time
import argparse
import os
import subprocess
import json
import csv
import re
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from collections import defaultdict
import threading
import platform

class MacWiFiScanner:
    """macOS WiFi scanner using system_profiler (works on all macOS versions)"""
    
    def __init__(self, interface=None, timeout=30):
        self.interface = interface
        self.timeout = timeout
        self.networks = {}
        self.start_time = None
        self.end_time = None
        self.is_running = False
        
        # Security assessment
        self.vulnerable_networks = []
        
        # Statistics
        self.stats = {
            'total_networks': 0,
            'encryption_types': defaultdict(int),
            'channels': defaultdict(int),
            'vendors': defaultdict(int),
            'security_scores': []
        }
        
        # Known vulnerable/default passwords (for warning)
        self.default_ssids = [
            'linksys', 'netgear', 'dlink', 'belkin', 'tp-link',
            'default', 'wireless', '2wire', 'hpsetup', 'asus',
            'admin', 'password', '123456', 'guest', 'public'
        ]
        
        # Common BSSID prefixes for vendor detection
        self.vendor_prefixes = {
            '00:11:22': 'Cisco',
            '00:0C:29': 'VMware',
            '00:50:56': 'VMware',
            '00:1A:A0': 'D-Link',
            '00:1D:0F': 'Intel',
            '00:1E:4F': 'Intel',
            '00:21:5C': 'Linksys',
            '00:22:69': 'Dell',
            '00:24:D6': 'Cisco',
            '00:25:9C': 'Apple',
            '00:26:08': 'Apple',
            '00:26:BB': 'Apple',
            '00:30:65': 'D-Link',
            '00:40:96': 'D-Link',
            '00:80:AD': 'Nokia',
            '00:90:4B': 'D-Link',
            '00:A0:C5': 'Linksys',
            '00:E0:98': 'D-Link',
            '00:E0:FD': 'Intel',
            '00:13:46': 'Belkin',
            '00:14:22': 'Dell',
            '00:15:5D': 'Microsoft',
            '00:16:01': 'Netgear',
            '00:16:CB': 'Netgear',
            '00:18:3E': 'Huawei',
            '00:1A:3F': 'Netgear',
            '00:1B:2F': 'D-Link',
            '00:1C:10': 'Apple',
            '00:1C:B3': 'D-Link',
            '00:1D:7E': 'Netgear',
            '00:1E:2A': 'Belkin',
            '00:23:DF': 'D-Link',
            '00:24:01': 'Netgear',
            '00:25:9C': 'Apple',
            '00:26:08': 'Apple',
            '00:26:BB': 'Apple',
            '00:30:65': 'D-Link',
            '00:40:96': 'D-Link',
            '00:80:AD': 'Nokia',
            '00:90:4B': 'D-Link',
            '00:A0:C5': 'Linksys',
            '00:E0:98': 'D-Link',
            '00:E0:FD': 'Intel',
            '08:10:74': 'Apple',
            '0C:47:C9': 'Netgear',
            '10:0D:7F': 'Netgear',
            '14:CC:20': 'Netgear',
            '18:34:51': 'TP-Link',
            '1C:7E:E5': 'TP-Link',
            '20:AA:4B': 'Apple',
            '28:6C:07': 'Apple',
            '2C:54:91': 'D-Link',
            '30:5A:3A': 'Apple',
            '34:12:98': 'Netgear',
            '34:96:72': 'TP-Link',
            '3C:37:86': 'Apple',
            '40:10:18': 'TP-Link',
            '40:16:9F': 'Netgear',
            '44:94:FC': 'Apple',
            '48:5B:39': 'Cisco',
            '4C:5E:0C': 'Cisco',
            '50:8B:9A': 'Belkin',
            '54:26:96': 'D-Link',
            '5C:CF:7F': 'Apple',
            '60:03:08': 'Netgear',
            '64:20:0C': 'Apple',
            '68:7F:74': 'D-Link',
            '6C:40:08': 'Apple',
            '70:3D:15': 'Netgear',
            '70:62:B8': 'Apple',
            '74:29:AF': 'TP-Link',
            '78:31:C1': 'TP-Link',
            '7C:6D:62': 'D-Link',
            '80:BE:05': 'Apple',
            '84:1B:5E': 'Netgear',
            '8C:93:4C': 'D-Link',
            '90:2E:1C': 'Apple',
            '94:0C:6D': 'Netgear',
            '98:01:A7': 'Apple',
            '9C:29:3E': 'Netgear',
            'A0:99:9B': 'D-Link',
            'A4:77:33': 'TP-Link',
            'A8:5E:45': 'Apple',
            'AC:7B:A1': 'Apple',
            'B0:75:D5': 'Apple',
            'B4:75:0E': 'D-Link',
            'B8:09:8A': 'Cisco',
            'BC:EC:5D': 'Apple',
            'C0:56:27': 'D-Link',
            'C4:6E:1F': 'Apple',
            'C8:3A:35': 'Netgear',
            'CC:08:8E': 'TP-Link',
            'D0:57:7B': 'Cisco',
            'D4:5D:64': 'TP-Link',
            'D8:50:E6': 'Apple',
            'DC:56:9F': 'Apple',
            'E0:55:3D': 'Netgear',
            'E4:F4:C6': 'Apple',
            'E8:94:F6': 'Apple',
            'EC:CB:30': 'D-Link',
            'F0:18:98': 'Netgear',
            'F4:37:B7': 'TP-Link',
            'F8:8B:F6': 'Netgear',
            'FC:34:97': 'Apple'
        }
    
    def scan_with_system_profiler(self):
        """Scan using macOS system_profiler"""
        print("[*] Scanning WiFi networks using system_profiler...")
        
        try:
            # Get WiFi data using system_profiler
            result = subprocess.run(
                ['system_profiler', 'SPAirPortDataType'],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                print(f"System_profiler failed with return code: {result.returncode}")
                return []
            
            output = result.stdout
            
            # Check if WiFi is enabled
            if 'Wi-Fi: Off' in output or 'AirPort: Off' in output:
                print("⚠️  WiFi is turned off. Please enable WiFi and try again.")
                return []
            
            # Parse the output
            networks = self.parse_system_profiler_output(output)
            
            if not networks:
                print("No WiFi networks found. Make sure WiFi is on and you're in range.")
                return []
            
            print(f"[+] Found {len(networks)} networks")
            return networks
            
        except FileNotFoundError:
            print("❌ system_profiler command not found. This is unusual for macOS.")
            return []
        except Exception as e:
            print(f"❌ Error scanning: {e}")
            return []
    
    def parse_system_profiler_output(self, output):
        """Parse system_profiler output to extract network information"""
        networks = []
        
        # Split by sections
        sections = output.split('Interfaces:')
        
        if len(sections) < 2:
            # Try alternative parsing
            sections = output.split('AirPort:')
        
        # Find the Wi-Fi section
        wifi_section = None
        for section in sections:
            if 'Wi-Fi' in section or 'AirPort' in section:
                wifi_section = section
                break
        
        if not wifi_section:
            # Try parsing the entire output
            wifi_section = output
        
        # Look for known networks
        lines = wifi_section.split('\n')
        
        current_network = {}
        in_network_list = False
        
        for line in lines:
            line = line.strip()
            
            # Look for the network list header
            if 'Networks:' in line:
                in_network_list = True
                continue
            
            # Only parse if we're in the network list
            if not in_network_list:
                continue
            
            # Skip empty lines
            if not line:
                if current_network and 'SSID' in current_network:
                    networks.append(current_network)
                    current_network = {}
                continue
            
            # Parse network fields
            if 'SSID:' in line:
                if current_network and 'SSID' in current_network:
                    networks.append(current_network)
                    current_network = {}
                ssid = line.split('SSID:')[1].strip()
                current_network['ssid'] = ssid
                
            elif 'BSSID:' in line:
                bssid = line.split('BSSID:')[1].strip()
                current_network['bssid'] = bssid
                current_network['vendor'] = self.get_vendor(bssid)
                
            elif 'RSSI:' in line:
                rssi_str = line.split('RSSI:')[1].strip()
                # Remove dBm suffix if present
                rssi_str = rssi_str.replace('dBm', '').strip()
                try:
                    current_network['rssi'] = int(rssi_str)
                except:
                    current_network['rssi'] = -100
                    
            elif 'Channel:' in line:
                channel_str = line.split('Channel:')[1].strip()
                # Extract channel number
                channel_match = re.search(r'(\d+)', channel_str)
                if channel_match:
                    current_network['channel'] = int(channel_match.group(1))
                else:
                    current_network['channel'] = 0
                    
            elif 'Security:' in line:
                security = line.split('Security:')[1].strip()
                current_network['security'] = security
                
            elif 'Signal:' in line:
                signal_str = line.split('Signal:')[1].strip()
                # Some versions use Signal instead of RSSI
                try:
                    signal_match = re.search(r'(-?\d+)', signal_str)
                    if signal_match:
                        current_network['rssi'] = int(signal_match.group(1))
                except:
                    pass
            
            elif 'State:' in line and 'connected' in line.lower():
                current_network['connected'] = True
        
        # Add the last network
        if current_network and 'SSID' in current_network:
            networks.append(current_network)
        
        # Clean up and process networks
        processed_networks = []
        for network in networks:
            # Ensure required fields exist
            if 'ssid' not in network:
                continue
            
            # Set defaults for missing fields
            network.setdefault('bssid', 'Unknown')
            network.setdefault('rssi', -100)
            network.setdefault('channel', 0)
            network.setdefault('security', 'Unknown')
            network.setdefault('vendor', self.get_vendor(network['bssid']))
            
            processed_networks.append(network)
            
            # Update statistics
            self.stats['total_networks'] += 1
            self.stats['encryption_types'][network['security']] += 1
            self.stats['channels'][str(network['channel'])] += 1
            if network['vendor']:
                self.stats['vendors'][network['vendor']] += 1
            
            # Store in networks dict
            bssid = network['bssid']
            if bssid not in self.networks:
                self.networks[bssid] = {
                    'ssid': network['ssid'],
                    'bssid': bssid,
                    'channel': network['channel'],
                    'encryption': network['security'],
                    'signal': network['rssi'],
                    'vendor': network['vendor'],
                    'first_seen': datetime.now(),
                    'last_seen': datetime.now(),
                    'beacon_count': 1,
                    'clients': [],
                    'security_score': 100,
                    'connected': network.get('connected', False)
                }
                self.assess_security(bssid)
        
        return processed_networks
    
    def get_vendor(self, mac):
        """Get vendor from MAC address OUI"""
        if not mac or mac == 'Unknown' or len(mac) < 8:
            return "Unknown"
        
        # Clean MAC address
        mac = mac.upper()
        # Remove colons and get first 6 characters (3 octets)
        mac_clean = mac.replace(':', '')
        if len(mac_clean) >= 6:
            prefix = mac_clean[:6]
            # Format as XX:XX:XX
            prefix_formatted = ':'.join([prefix[i:i+2] for i in range(0, 6, 2)])
            return self.vendor_prefixes.get(prefix_formatted, "Unknown")
        
        return "Unknown"
    
    def assess_security(self, bssid):
        """Assess security of a network"""
        network = self.networks.get(bssid)
        if not network:
            return
        
        score = 100
        issues = []
        
        # Check encryption
        encryption = network['encryption']
        if 'Open' in encryption or 'None' in encryption or not encryption:
            score -= 30
            issues.append("Open network (no encryption)")
        elif 'WEP' in encryption:
            score -= 20
            issues.append("WEP encryption (weak)")
        elif 'WPA2' not in encryption and 'WPA3' not in encryption:
            if 'WPA' in encryption:
                score -= 10
                issues.append("Only WPA (not WPA2/WPA3)")
        
        # Check for default SSID
        ssid = network['ssid'].lower()
        if any(default in ssid for default in self.default_ssids):
            score -= 10
            issues.append("Default/weak SSID")
        
        # Check signal strength
        if network['signal'] < -80:
            score -= 5
            issues.append("Very weak signal")
        
        # Check vendor vulnerabilities
        if network['vendor'] in ['Linksys', 'Netgear', 'D-Link']:
            if 'default' in ssid or 'linksys' in ssid or 'netgear' in ssid:
                score -= 10
                issues.append("Default router configuration")
        
        # Store assessment
        network['security_score'] = max(0, score)
        if issues:
            network['security_issues'] = issues
            if score < 70:
                self.vulnerable_networks.append(bssid)
        
        self.stats['security_scores'].append(score)
    
    def start_scan(self):
        """Start WiFi scanning on macOS"""
        print("="*70)
        print("🍎 MACOS WIFI SCANNER")
        print("="*70)
        print(f"Scan duration: {self.timeout} seconds")
        print("="*70)
        
        self.start_time = datetime.now()
        self.is_running = True
        
        print(f"\n[*] Started scanning at {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("[*] This may take a moment...\n")
        
        try:
            # Perform scan using system_profiler
            networks = self.scan_with_system_profiler()
            
            # If no networks found with system_profiler, try alternative
            if not networks:
                print("\n[*] Trying alternative scan method...")
                networks = self.scan_with_airport_alt()
            
        except KeyboardInterrupt:
            print("\n\n[!] Scanning interrupted by user")
        except Exception as e:
            print(f"\n[!] Error during scanning: {e}")
        finally:
            self.stop_scan()
        
        return self.networks
    
    def scan_with_airport_alt(self):
        """Alternative scan method using airport command if available"""
        # Try to find airport in common locations
        airport_paths = [
            '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport',
            '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/A/Resources/airport',
            '/usr/sbin/airport',
            '/usr/local/bin/airport'
        ]
        
        for path in airport_paths:
            if os.path.exists(path) and os.access(path, os.X_OK):
                print(f"[*] Found airport at: {path}")
                try:
                    result = subprocess.run([path, '-s'], capture_output=True, text=True)
                    if result.returncode == 0 and result.stdout:
                        return self.parse_airport_output(result.stdout)
                except:
                    continue
        
        return []
    
    def parse_airport_output(self, output):
        """Parse airport command output"""
        networks = []
        lines = output.strip().split('\n')
        
        if len(lines) < 2:
            return []
        
        for line in lines[1:]:
            if not line.strip():
                continue
            
            parts = line.split()
            if len(parts) < 6:
                continue
            
            try:
                # Find BSSID pattern
                bssid_idx = -1
                for i, part in enumerate(parts):
                    if re.match(r'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', part):
                        bssid_idx = i
                        break
                
                if bssid_idx == -1:
                    continue
                
                ssid = ' '.join(parts[:bssid_idx])
                if not ssid:
                    ssid = '<Hidden>'
                
                bssid = parts[bssid_idx]
                rssi = int(parts[bssid_idx + 1]) if parts[bssid_idx + 1].lstrip('-').isdigit() else -100
                channel = int(parts[bssid_idx + 2]) if parts[bssid_idx + 2].isdigit() else 0
                security = ' '.join(parts[bssid_idx + 4:]) if bssid_idx + 4 < len(parts) else 'Unknown'
                security = security.replace('(', '').replace(')', '').strip()
                
                network = {
                    'ssid': ssid,
                    'bssid': bssid,
                    'rssi': rssi,
                    'channel': channel,
                    'security': security,
                    'vendor': self.get_vendor(bssid)
                }
                
                networks.append(network)
                
                # Update stats and store
                self.stats['total_networks'] += 1
                self.stats['encryption_types'][security] += 1
                self.stats['channels'][str(channel)] += 1
                if network['vendor']:
                    self.stats['vendors'][network['vendor']] += 1
                
                if bssid not in self.networks:
                    self.networks[bssid] = {
                        'ssid': ssid,
                        'bssid': bssid,
                        'channel': channel,
                        'encryption': security,
                        'signal': rssi,
                        'vendor': network['vendor'],
                        'first_seen': datetime.now(),
                        'last_seen': datetime.now(),
                        'beacon_count': 1,
                        'clients': [],
                        'security_score': 100
                    }
                    self.assess_security(bssid)
                    
            except Exception as e:
                continue
        
        return networks
    
    def stop_scan(self):
        """Stop scanning and display summary"""
        self.is_running = False
        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds() if self.end_time else 0
        
        print("\n" + "="*70)
        print("SCAN COMPLETE")
        print("="*70)
        print(f"Started:   {self.start_time.strftime('%Y-%m-%d %H:%M:%S') if self.start_time else 'N/A'}")
        print(f"Ended:     {self.end_time.strftime('%Y-%m-%d %H:%M:%S') if self.end_time else 'N/A'}")
        print(f"Duration:  {duration:.2f} seconds")
        print(f"Networks:  {len(self.networks)}")
        print("="*70)
    
    def display_networks(self):
        """Display discovered networks"""
        if not self.networks:
            print("\n❌ No WiFi networks found!")
            print("\nTroubleshooting:")
            print("1. Make sure WiFi is turned ON")
            print("2. Go to System Preferences > Network")
            print("3. Move closer to a WiFi router")
            print("4. Try: sudo python3 wifi_scan.py -t 60")
            return
        
        print("\n" + "="*80)
        print("📡 DISCOVERED NETWORKS")
        print("="*80)
        print(f"{'SSID':<30} {'BSSID':<20} {'CH':<6} {'Signal':<8} {'Security':<20} {'Score'}")
        print("-"*80)
        
        # Sort by signal strength
        sorted_networks = sorted(self.networks.values(), 
                               key=lambda x: x['signal'], reverse=True)
        
        for network in sorted_networks:
            ssid = network['ssid'][:28] if len(network['ssid']) > 28 else network['ssid']
            if network['ssid'] == '<Hidden>':
                ssid = '<Hidden>'
            
            signal_str = f"{network['signal']}dBm"
            
            # Score
            score = network.get('security_score', 0)
            if score >= 80:
                score_str = f"✅ {score}%"
            elif score >= 60:
                score_str = f"🔶 {score}%"
            else:
                score_str = f"⚠️ {score}%"
            
            # Add connected indicator
            connected = "🔗 " if network.get('connected', False) else "   "
            
            print(f"{connected}{ssid:<27} {network['bssid']:<20} "
                  f"{network['channel']:<6} {signal_str:<8} "
                  f"{network['encryption'][:19]:<20} {score_str}")
            
            # Print security issues if any
            if 'security_issues' in network and network['security_issues']:
                for issue in network['security_issues'][:2]:
                    print(f"     ⚠️  {issue}")
                if len(network['security_issues']) > 2:
                    print(f"     ... and {len(network['security_issues'])-2} more issues")
    
    def display_statistics(self):
        """Display detailed statistics"""
        if not self.networks:
            return
        
        print("\n" + "="*70)
        print("📊 STATISTICS")
        print("="*70)
        
        # Channel distribution
        if self.stats['channels']:
            print("\n📻 Channel Distribution:")
            total = sum(self.stats['channels'].values())
            for channel, count in sorted(self.stats['channels'].items(), 
                                        key=lambda x: int(x[0]) if x[0].isdigit() else 0)[:20]:
                bar = '█' * (count * 30 // max(1, total))
                print(f"  Channel {channel:4}: {bar} {count}")
        
        # Encryption types
        if self.stats['encryption_types']:
            print("\n🔐 Encryption Types:")
            total = sum(self.stats['encryption_types'].values())
            for enc, count in sorted(self.stats['encryption_types'].items(), 
                                    key=lambda x: x[1], reverse=True):
                percentage = (count / max(1, total) * 100)
                bar = '█' * (int(percentage // 2))
                print(f"  {enc[:15]:<15}: {bar} {count} ({percentage:.1f}%)")
        
        # Vendors
        if self.stats['vendors']:
            print("\n🏭 Hardware Vendors:")
            for vendor, count in sorted(self.stats['vendors'].items(), 
                                       key=lambda x: x[1], reverse=True)[:10]:
                print(f"  {vendor:<15}: {count}")
        
        # Security summary
        if self.stats['security_scores']:
            print("\n🛡️  Security Summary:")
            avg_score = sum(self.stats['security_scores']) / len(self.stats['security_scores'])
            print(f"  Average security score: {avg_score:.1f}%")
            print(f"  Secure networks (≥80%): {sum(1 for s in self.stats['security_scores'] if s >= 80)}")
            print(f"  Vulnerable networks (<60%): {sum(1 for s in self.stats['security_scores'] if s < 60)}")
    
    def export_csv(self, filename=None):
        """Export to CSV"""
        if not self.networks:
            print("No data to export")
            return
        
        if filename is None:
            filename = f"wifi_scan_mac_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        try:
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['SSID', 'BSSID', 'Channel', 'Signal', 
                               'Security', 'Vendor', 'Security Score', 'Issues', 'Connected'])
                
                for network in self.networks.values():
                    writer.writerow([
                        network.get('ssid', ''),
                        network.get('bssid', ''),
                        network.get('channel', ''),
                        network.get('signal', ''),
                        network.get('encryption', ''),
                        network.get('vendor', ''),
                        network.get('security_score', 0),
                        '; '.join(network.get('security_issues', [])),
                        network.get('connected', False)
                    ])
            
            print(f"✅ CSV exported to: {filename}")
        except Exception as e:
            print(f"❌ Failed to export CSV: {e}")
    
    def export_json(self, filename=None):
        """Export to JSON"""
        if not self.networks:
            print("No data to export")
            return
        
        if filename is None:
            filename = f"wifi_scan_mac_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            # Convert datetime objects to strings
            networks_list = []
            for network in self.networks.values():
                network_copy = network.copy()
                network_copy['first_seen'] = network_copy['first_seen'].isoformat()
                network_copy['last_seen'] = network_copy['last_seen'].isoformat()
                networks_list.append(network_copy)
            
            data = {
                'scan_time': datetime.now().isoformat(),
                'interface': self.interface,
                'total_networks': len(self.networks),
                'networks': networks_list,
                'statistics': {
                    'total_networks': len(self.networks),
                    'encryption_types': dict(self.stats['encryption_types']),
                    'channels': dict(self.stats['channels']),
                    'vendors': dict(self.stats['vendors'])
                },
                'vulnerable_networks': self.vulnerable_networks
            }
            
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            
            print(f"✅ JSON exported to: {filename}")
        except Exception as e:
            print(f"❌ Failed to export JSON: {e}")

def main():
    parser = argparse.ArgumentParser(
        description='macOS WiFi Scanner - Works on all macOS versions',
        epilog='Example: python3 wifi_scan.py -t 60'
    )
    
    parser.add_argument('-i', '--interface', 
                       help='WiFi interface (e.g., en0, en1). Auto-detected if not specified')
    parser.add_argument('-t', '--timeout', type=int, default=30,
                       help='Scan duration in seconds (default: 30)')
    parser.add_argument('-c', '--csv', 
                       help='Export results to CSV file')
    parser.add_argument('-j', '--json',
                       help='Export results to JSON file')
    parser.add_argument('--no-stats', action='store_true',
                       help='Skip detailed statistics')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    # Create scanner
    scanner = MacWiFiScanner(
        interface=args.interface,
        timeout=args.timeout
    )
    
    # Start scan
    networks = scanner.start_scan()
    
    # Display results
    if networks:
        scanner.display_networks()
        
        if not args.no_stats:
            scanner.display_statistics()
        
        # Export if requested
        if args.csv:
            scanner.export_csv(args.csv)
        if args.json:
            scanner.export_json(args.json)
        
        # Security recommendations
        if scanner.vulnerable_networks:
            print("\n" + "="*70)
            print("⚠️  SECURITY RECOMMENDATIONS")
            print("="*70)
            for bssid in scanner.vulnerable_networks[:5]:
                network = scanner.networks[bssid]
                print(f"\n⚠️  {network['ssid']} ({network['bssid']}):")
                print(f"   Security Score: {network['security_score']}%")
                if 'security_issues' in network:
                    for issue in network['security_issues']:
                        print(f"   - {issue}")
                print(f"   💡 Recommendation: Use WPA2/WPA3 with strong password")
            
            if len(scanner.vulnerable_networks) > 5:
                print(f"\n... and {len(scanner.vulnerable_networks)-5} more vulnerable networks")
        else:
            print("\n✅ All networks appear to use modern security!")
    else:
        print("\nNo WiFi networks found. Try:")
        print("1. Make sure WiFi is turned ON")
        print("2. Go to System Preferences > Network")
        print("3. Move closer to WiFi networks")
        print("4. Try: python3 wifi_scan.py -t 60")

if __name__ == "__main__":
    main()