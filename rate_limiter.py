"""
Rate Limiting for Zero Trust
Prevent API abuse and brute-force attacks
"""

import logging
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import request, jsonify
from collections import defaultdict
import threading

logger = logging.getLogger(__name__)

class RateLimiter:
    """In-memory rate limiter"""
    
    def __init__(self):
        self.requests = defaultdict(list)
        self.lock = threading.Lock()
        self.cleanup_interval = 300  # Cleanup every 5 minutes
        self.last_cleanup = datetime.now(timezone.utc)
    
    def _cleanup_old_requests(self):
        """Remove old request records"""
        now = datetime.now(timezone.utc)
        
        if (now - self.last_cleanup).seconds < self.cleanup_interval:
            return
        
        with self.lock:
            cutoff = now - timedelta(hours=1)
            for key in list(self.requests.keys()):
                self.requests[key] = [
                    ts for ts in self.requests[key] 
                    if ts > cutoff
                ]
                if not self.requests[key]:
                    del self.requests[key]
            
            self.last_cleanup = now
    
    def is_allowed(self, key, max_requests, window_seconds):
        """
        Check if request is allowed
        key: identifier (IP, user_id, etc.)
        max_requests: maximum requests allowed
        window_seconds: time window in seconds
        """
        self._cleanup_old_requests()
        
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=window_seconds)
        
        with self.lock:
            # Get recent requests
            recent_requests = [
                ts for ts in self.requests[key]
                if ts > cutoff
            ]
            
            if len(recent_requests) >= max_requests:
                logger.warning('Rate limit exceeded for %s: %d requests in %d seconds',
                             key, len(recent_requests), window_seconds)
                return False
            
            # Add current request
            self.requests[key].append(now)
            return True
    
    def get_request_count(self, key, window_seconds):
        """Get number of requests in time window"""
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=window_seconds)
        
        with self.lock:
            return len([ts for ts in self.requests[key] if ts > cutoff])

# Global rate limiter instance
rate_limiter = RateLimiter()

def rate_limit(max_requests=10, window_seconds=60, key_func=None):
    """
    Rate limiting decorator
    max_requests: maximum requests allowed
    window_seconds: time window
    key_func: function to generate key (default: IP address)
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Generate key
            if key_func:
                key = key_func()
            else:
                key = request.remote_addr or 'unknown'
            
            # Check rate limit
            if not rate_limiter.is_allowed(key, max_requests, window_seconds):
                logger.warning('Rate limit exceeded for %s on %s', key, request.endpoint)
                
                return jsonify({
                    'error': 'Rate limit exceeded',
                    'message': f'Too many requests. Maximum {max_requests} requests per {window_seconds} seconds.',
                    'retry_after': window_seconds
                }), 429
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

def login_rate_limit(max_attempts=5, window_seconds=300):
    """
    Special rate limiter for login attempts
    More strict to prevent brute-force
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Use IP + username as key
            username = request.form.get('username', 'unknown')
            key = f"login_{request.remote_addr}_{username}"
            
            if not rate_limiter.is_allowed(key, max_attempts, window_seconds):
                logger.warning('Login rate limit exceeded for %s from %s', 
                             username, request.remote_addr)
                
                from flask import flash, render_template
                flash(f'Too many login attempts. Please try again in {window_seconds//60} minutes.', 'error')
                return render_template('login.html'), 429
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator
