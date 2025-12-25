from flask import Flask, render_template, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import re
import email
from email import policy
from email.parser import BytesParser
from datetime import datetime
import secrets
from urllib.parse import urlparse
import tempfile

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Use temp directory for Vercel serverless
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()

# In-memory user storage (replace with database in production)
users = {}

# Suspicious patterns and indicators
SUSPICIOUS_KEYWORDS = [
    'urgent', 'verify account', 'suspended', 'confirm identity', 'click here',
    'verify your account', 'unusual activity', 'security alert', 'act now',
    'limited time', 'expire', 'update payment', 'billing problem', 'prize',
    'winner', 'congratulations', 'claim', 'free money', 'nigerian prince',
    'inheritance', 'tax refund', 'irs', 'bitcoin', 'cryptocurrency wallet'
]

SUSPICIOUS_DOMAINS = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click',
    '.link', '.zip', '.download'
]

LEGITIMATE_DOMAINS = [
    'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'facebook.com',
    'linkedin.com', 'twitter.com', 'github.com', 'stackoverflow.com'
]


class PhishingDetector:
    """Rule-based phishing detection system"""
    
    def __init__(self):
        self.risk_score = 0
        self.flags = []
        self.details = {}
    
    def analyze_email(self, email_data):
        """Analyze email using rule-based heuristics"""
        self.risk_score = 0
        self.flags = []
        self.details = {}
        
        sender = email_data.get('sender', '')
        subject = email_data.get('subject', '')
        body = email_data.get('body', '')
        headers = email_data.get('headers', {})
        
        # Run all detection rules
        self._check_sender_authenticity(sender, headers)
        self._check_subject_patterns(subject)
        self._check_body_content(body)
        self._check_urls(body)
        self._check_attachments(email_data.get('attachments', []))
        self._check_headers(headers)
        self._check_urgency_language(subject, body)
        
        # Calculate final classification
        classification = self._get_classification()
        
        return {
            'risk_score': self.risk_score,
            'classification': classification,
            'flags': self.flags,
            'details': self.details
        }
    
    def _check_sender_authenticity(self, sender, headers):
        """Check sender email and domain authenticity"""
        if not sender:
            self.risk_score += 20
            self.flags.append('Missing sender information')
            return
        
        # Extract domain
        match = re.search(r'@([\w\.-]+)', sender)
        if match:
            domain = match.group(1).lower()
            self.details['sender_domain'] = domain
            
            # Check for suspicious TLDs
            for suspicious_tld in SUSPICIOUS_DOMAINS:
                if domain.endswith(suspicious_tld):
                    self.risk_score += 25
                    self.flags.append(f'Suspicious domain TLD: {suspicious_tld}')
            
            # Check for domain spoofing attempts
            for legit_domain in LEGITIMATE_DOMAINS:
                if legit_domain in domain and domain != legit_domain:
                    self.risk_score += 40
                    self.flags.append(f'Possible domain spoofing: mimicking {legit_domain}')
        
        # Check for display name mismatch
        display_match = re.match(r'^(.+?)\s*<(.+?)>$', sender)
        if display_match:
            display_name = display_match.group(1).strip()
            email_addr = display_match.group(2).strip()
            
            # Check if display name contains legitimate company but email doesn't
            for legit_domain in LEGITIMATE_DOMAINS:
                company_name = legit_domain.split('.')[0]
                if company_name.lower() in display_name.lower():
                    if legit_domain not in email_addr.lower():
                        self.risk_score += 35
                        self.flags.append(f'Display name spoofing: claims to be {company_name}')
        
        # Check SPF, DKIM, DMARC from headers
        spf = headers.get('Received-SPF', '').lower()
        if 'fail' in spf:
            self.risk_score += 30
            self.flags.append('SPF authentication failed')
        
        dkim = headers.get('DKIM-Signature', '')
        if not dkim and self.risk_score > 0:
            self.risk_score += 10
            self.flags.append('Missing DKIM signature')
    
    def _check_subject_patterns(self, subject):
        """Analyze subject line for phishing patterns"""
        if not subject:
            return
        
        subject_lower = subject.lower()
        
        # Check for suspicious keywords in subject
        found_keywords = []
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in subject_lower:
                found_keywords.append(keyword)
        
        if found_keywords:
            self.risk_score += len(found_keywords) * 8
            self.flags.append(f'Suspicious keywords in subject: {", ".join(found_keywords[:3])}')
        
        # Check for excessive punctuation
        if subject.count('!') >= 2 or subject.count('?') >= 2:
            self.risk_score += 10
            self.flags.append('Excessive punctuation in subject')
        
        # Check for all caps
        if subject.isupper() and len(subject) > 10:
            self.risk_score += 12
            self.flags.append('Subject in all capitals')
    
    def _check_body_content(self, body):
        """Analyze email body content"""
        if not body:
            return
        
        body_lower = body.lower()
        
        # Check for suspicious keywords in body
        found_keywords = []
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in body_lower:
                found_keywords.append(keyword)
        
        if found_keywords:
            self.risk_score += len(found_keywords) * 5
            if len(found_keywords) > 3:
                self.flags.append(f'Multiple suspicious keywords: {", ".join(found_keywords[:3])}...')
        
        # Check for requests for personal information
        personal_info_patterns = [
            r'social security', r'credit card', r'password', r'pin\s*code',
            r'account\s*number', r'routing\s*number', r'date\s*of\s*birth'
        ]
        
        for pattern in personal_info_patterns:
            if re.search(pattern, body_lower):
                self.risk_score += 25
                self.flags.append('Requests personal/financial information')
                break
        
        # Check for poor grammar/spelling indicators
        if re.search(r'\s{3,}', body) or body.count('\n\n\n') > 2:
            self.risk_score += 8
            self.flags.append('Poor formatting detected')
    
    def _check_urls(self, body):
        """Extract and analyze URLs in email body"""
        if not body:
            return
        
        # Find all URLs
        url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
        urls = re.findall(url_pattern, body)
        
        if not urls:
            return
        
        self.details['url_count'] = len(urls)
        suspicious_urls = []
        
        for url in urls[:10]:  # Check first 10 URLs
            parsed = urlparse(url if url.startswith('http') else 'http://' + url)
            domain = parsed.netloc.lower()
            
            # Check for IP addresses instead of domains
            if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                self.risk_score += 30
                suspicious_urls.append(url[:50])
                self.flags.append('URL uses IP address instead of domain')
            
            # Check for suspicious TLDs
            for suspicious_tld in SUSPICIOUS_DOMAINS:
                if domain.endswith(suspicious_tld):
                    self.risk_score += 20
                    suspicious_urls.append(url[:50])
                    break
            
            # Check for URL shorteners
            shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly']
            if any(shortener in domain for shortener in shorteners):
                self.risk_score += 15
                self.flags.append('Contains URL shortener links')
            
            # Check for misleading URLs
            if '@' in parsed.netloc:
                self.risk_score += 35
                self.flags.append('Misleading URL with @ symbol')
        
        if len(urls) > 5:
            self.risk_score += 10
            self.flags.append(f'Excessive number of URLs: {len(urls)}')
        
        if suspicious_urls:
            self.details['suspicious_urls'] = suspicious_urls[:3]
    
    def _check_attachments(self, attachments):
        """Analyze email attachments"""
        if not attachments:
            return
        
        suspicious_extensions = [
            '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.js',
            '.jar', '.zip', '.rar', '.iso', '.dll'
        ]
        
        for attachment in attachments:
            name = attachment.lower()
            for ext in suspicious_extensions:
                if name.endswith(ext):
                    self.risk_score += 40
                    self.flags.append(f'Suspicious attachment type: {ext}')
                    break
            
            # Check for double extensions
            if name.count('.') >= 2:
                self.risk_score += 25
                self.flags.append('Double extension in attachment')
    
    def _check_headers(self, headers):
        """Analyze email headers"""
        # Check for mismatched return paths
        from_addr = headers.get('From', '')
        return_path = headers.get('Return-Path', '')
        
        if from_addr and return_path:
            from_domain = re.search(r'@([\w\.-]+)', from_addr)
            return_domain = re.search(r'@([\w\.-]+)', return_path)
            
            if from_domain and return_domain:
                if from_domain.group(1) != return_domain.group(1):
                    self.risk_score += 20
                    self.flags.append('Mismatched sender and return-path domains')
        
        # Check for multiple received headers (potential forwarding)
        received = headers.get('Received', '')
        if isinstance(received, list):
            if len(received) > 5:
                self.risk_score += 10
                self.flags.append('Multiple mail server hops detected')
    
    def _check_urgency_language(self, subject, body):
        """Check for urgency and pressure tactics"""
        text = (subject + ' ' + body).lower()
        
        urgency_patterns = [
            'immediately', 'urgent', 'action required', 'act now',
            'within 24 hours', 'expire', 'suspend', 'limited time',
            'today only', 'last chance'
        ]
        
        urgency_count = sum(1 for pattern in urgency_patterns if pattern in text)
        
        if urgency_count >= 3:
            self.risk_score += 20
            self.flags.append('Creates false sense of urgency')
        elif urgency_count >= 2:
            self.risk_score += 10
    
    def _get_classification(self):
        """Determine final classification based on risk score"""
        if self.risk_score >= 60:
            return 'PHISHING'
        elif self.risk_score >= 30:
            return 'SUSPICIOUS'
        else:
            return 'SAFE'


def parse_eml_file(file_path):
    """Parse .eml file and extract relevant information"""
    with open(file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)
    
    # Extract headers
    headers = {}
    for key in msg.keys():
        headers[key] = msg.get(key)
    
    # Extract sender
    sender = msg.get('From', '')
    subject = msg.get('Subject', '')
    
    # Extract body
    body = ''
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/plain':
                body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
    else:
        body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
    
    # Extract attachments
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_disposition() == 'attachment':
                attachments.append(part.get_filename() or 'unknown')
    
    return {
        'sender': sender,
        'subject': subject,
        'body': body,
        'headers': headers,
        'attachments': attachments
    }


# Routes
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')
    
    # Validation
    if not username or not email or not password:
        return jsonify({'success': False, 'message': 'All fields are required'}), 400
    
    if len(password) < 8:
        return jsonify({'success': False, 'message': 'Password must be at least 8 characters'}), 400
    
    if username in users:
        return jsonify({'success': False, 'message': 'Username already exists'}), 400
    
    # Store user
    users[username] = {
        'email': email,
        'password': generate_password_hash(password),
        'created_at': datetime.now().isoformat()
    }
    
    return jsonify({'success': True, 'message': 'Registration successful'})


@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    if not username or not password:
        return jsonify({'success': False, 'message': 'All fields are required'}), 400
    
    user = users.get(username)
    if not user or not check_password_hash(user['password'], password):
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
    
    session['username'] = username
    return jsonify({'success': True, 'message': 'Login successful'})


@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    return jsonify({'success': True})


@app.route('/api/analyze-manual', methods=['POST'])
def analyze_manual():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    data = request.json
    email_data = {
        'sender': data.get('sender', ''),
        'subject': data.get('subject', ''),
        'body': data.get('body', ''),
        'headers': {},
        'attachments': []
    }
    
    detector = PhishingDetector()
    result = detector.analyze_email(email_data)
    
    return jsonify({
        'success': True,
        'result': result
    })


@app.route('/api/analyze-file', methods=['POST'])
def analyze_file():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'}), 400
    
    if not file.filename.endswith('.eml'):
        return jsonify({'success': False, 'message': 'Only .eml files are supported'}), 400
    
    # Save file
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    try:
        # Parse email file
        email_data = parse_eml_file(filepath)
        
        # Analyze
        detector = PhishingDetector()
        result = detector.analyze_email(email_data)
        
        # Clean up
        os.remove(filepath)
        
        return jsonify({
            'success': True,
            'result': result,
            'email_preview': {
                'sender': email_data['sender'],
                'subject': email_data['subject'],
                'body_preview': email_data['body'][:200] + '...' if len(email_data['body']) > 200 else email_data['body']
            }
        })
    
    except Exception as e:
        if os.path.exists(filepath):
            os.remove(filepath)
        return jsonify({'success': False, 'message': f'Error parsing file: {str(e)}'}), 500


if __name__ == '__main__':
    app.run(debug=True, port=5000)
