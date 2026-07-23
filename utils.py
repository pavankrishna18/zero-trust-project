"""
Utility Functions
Helper functions for common tasks
"""

import qrcode
import io
import base64
import re
import logging

logger = logging.getLogger(__name__)

def generate_qr_code(data):
    """
    Generate QR code from data
    
    Args:
        data: Data to encode in QR code
    
    Returns:
        Base64 encoded QR code image
    """
    try:
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        img_base64 = base64.b64encode(buffer.getvalue()).decode()
        
        return f"data:image/png;base64,{img_base64}"
    except Exception as e:
        logger.error('Error generating QR code: %s', str(e))
        return None

def validate_password_strength(password):
    """
    Validate password strength
    
    Args:
        password: Password to validate
    
    Returns:
        {'valid': bool, 'errors': [list of error messages]}
    """
    errors = []
    
    # Minimum length
    if len(password) < 8:
        errors.append('Password must be at least 8 characters long')
    
    # At least one uppercase letter
    if not re.search(r'[A-Z]', password):
        errors.append('Password must contain at least one uppercase letter')
    
    # At least one lowercase letter
    if not re.search(r'[a-z]', password):
        errors.append('Password must contain at least one lowercase letter')
    
    # At least one digit
    if not re.search(r'\d', password):
        errors.append('Password must contain at least one number')
    
    # At least one special character
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append('Password must contain at least one special character (!@#$%^&*)')
    
    return {
        'valid': len(errors) == 0,
        'errors': errors
    }

def validate_email(email):
    """
    Validate email format
    
    Args:
        email: Email to validate
    
    Returns:
        Boolean - True if valid, False otherwise
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_username(username):
    """
    Validate username format
    
    Args:
        username: Username to validate
    
    Returns:
        Boolean - True if valid, False otherwise
    """
    # Username: 3-20 characters, alphanumeric and underscores only
    pattern = r'^[a-zA-Z0-9_]{3,20}$'
    return bool(re.match(pattern, username))

def sanitize_input(data):
    """
    Sanitize user input
    
    Args:
        data: Input data to sanitize
    
    Returns:
        Sanitized string
    """
    if not isinstance(data, str):
        return str(data)
    
    # Remove leading/trailing whitespace
    data = data.strip()
    
    # Remove potentially dangerous characters
    dangerous_chars = ['<', '>', '"', "'", '%', ';', '&']
    for char in dangerous_chars:
        data = data.replace(char, '')
    
    return data

def get_client_ip(request):
    """
    Get client IP address from request
    
    Args:
        request: Flask request object
    
    Returns:
        Client IP address string
    """
    if request.environ.get('HTTP_CF_CONNECTING_IP'):
        return request.environ.get('HTTP_CF_CONNECTING_IP')
    return request.remote_addr

def get_user_agent(request):
    """
    Get user agent from request
    
    Args:
        request: Flask request object
    
    Returns:
        User agent string
    """
    return request.headers.get('User-Agent', 'Unknown')
