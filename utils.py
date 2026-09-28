"""
Semgrep Demo App - Utility Functions
DO NOT use in production. Contains deliberate security flaws.
"""

import hashlib
import hmac
import requests
import xml.etree.ElementTree as ET


# VULNERABILITY 1: Weak cryptographic hashing for passwords
# Semgrep rule: python.lang.security.audit.insecure-hash-function
def hash_password(password):
    """Hash a password using MD5 — this is cryptographically broken."""
    # BAD: MD5 is not suitable for password hashing
    return hashlib.md5(password.encode()).hexdigest()


def verify_password(password, stored_hash):
    """Verify a password against an MD5 hash."""
    # BAD: MD5 comparison for password verification
    return hashlib.md5(password.encode()).hexdigest() == stored_hash


def hash_token(token):
    """Hash a token using SHA1 — also weak."""
    # BAD: SHA1 is deprecated for security-sensitive use
    return hashlib.sha1(token.encode()).hexdigest()


# VULNERABILITY 2: Hardcoded AWS credentials
# Semgrep rule: python.lang.security.audit.hardcoded-credentials
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_REGION = "us-east-1"
DATABASE_URL = "postgresql://admin:password123@prod-db.example.com:5432/maindb"


def get_aws_session():
    """Create a boto3 session with hardcoded credentials."""
    # BAD: Credentials should come from environment variables or IAM roles
    import boto3
    return boto3.Session(
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION,
    )


# VULNERABILITY 3: Server-Side Request Forgery (SSRF)
# Semgrep rule: python.lang.security.audit.ssrf-requests
def fetch_url(url):
    """Fetch content from a URL — no validation on the URL."""
    # BAD: User-controlled URL passed directly to requests.get
    response = requests.get(url)
    return response.text


def fetch_avatar(user_provided_url):
    """Download a user's avatar from a URL they provide."""
    # BAD: SSRF — user can point this to internal services (169.254.169.254, etc.)
    response = requests.get(user_provided_url, timeout=10)
    return response.content


def proxy_request(target_url, method="GET"):
    """Proxy a request to a user-specified URL."""
    # BAD: Unrestricted SSRF proxy
    if method == "GET":
        return requests.get(target_url).text
    elif method == "POST":
        return requests.post(target_url).text


# BONUS: XML External Entity (XXE) vulnerability
def parse_xml_input(xml_string):
    """Parse XML input from user — vulnerable to XXE."""
    # BAD: Default XML parser is vulnerable to XXE attacks
    tree = ET.fromstring(xml_string)
    return tree


# BONUS: Insecure temporary file usage
import tempfile
def save_temp_data(data):
    """Save data to a temp file insecurely."""
    # BAD: Predictable temp file
    tmp = tempfile.mktemp(suffix=".txt")
    with open(tmp, "w") as f:
        f.write(data)
    return tmp
