"""
SSL/TLS Configuration for Zero Trust
Force HTTPS and manage certificates
"""

import logging
from flask import request, redirect
from functools import wraps

logger = logging.getLogger(__name__)

class SSLConfig:
    """SSL/TLS configuration and enforcement"""
    
    @staticmethod
    def force_https():
        """Force HTTPS redirect"""
        if not request.is_secure:
            url = request.url.replace('http://', 'https://', 1)
            return redirect(url, code=301)
    
    @staticmethod
    def generate_self_signed_cert():
        """
        Generate self-signed certificate for development
        Returns: (cert_path, key_path)
        """
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.backends import default_backend
            import datetime
            
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            # Generate certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ZeroTrustX"),
                x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.DNSName("127.0.0.1"),
                ]),
                critical=False,
            ).sign(private_key, hashes.SHA256(), default_backend())
            
            # Write certificate
            cert_path = "cert.pem"
            key_path = "key.pem"
            
            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            with open(key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            logger.info('Self-signed certificate generated: %s, %s', cert_path, key_path)
            return (cert_path, key_path)
        
        except Exception as e:
            logger.error('Certificate generation failed: %s', str(e))
            return None, None

def require_https(f):
    """Decorator to force HTTPS on specific routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not request.is_secure and not request.host.startswith('127.0.0.1') and not request.host.startswith('localhost'):
            return redirect(request.url.replace('http://', 'https://'))
        return f(*args, **kwargs)
    return decorated_function
