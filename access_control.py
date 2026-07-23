"""
Access Control Service
Handles role-based and rule-based access control with policies
"""

from models import AccessRule, User
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)

class AccessControlService:
    """Centralized access control evaluation"""
    
    @staticmethod
    def evaluate_access(user, resource, action, context=None):
        """Evaluate if user has access to resource"""
        
        if context is None:
            context = {}
        
        # ✅ SUPER ADMIN ALWAYS HAS FULL ACCESS
        if user.is_super_admin:
            return {'allowed': True, 'reason': 'Super admin full access'}
        
        # Check if account is locked
        if user.is_locked:
            return {'allowed': False, 'reason': 'Account is locked'}
        
        # Get applicable rules for this user's role
        rules = AccessRule.query.filter_by(
            role=user.role,
            resource=resource,
            is_active=True
        ).all()
        
        # If no rules exist for this resource/role, deny access
        if not rules:
            return {'allowed': False, 'reason': f'No access rules for {resource}'}
        
        # Check each rule
        for rule in rules:
            # Check if rule allows this action
            if rule.action not in ['read', 'write', 'delete']:
                continue
            
            if action == 'read' and rule.action in ['read', 'write']:
                # Check additional conditions
                
                # 1. Check trusted device requirement
                if rule.require_trusted_device:
                    is_trusted = context.get('is_trusted_device', False)
                    if not is_trusted:
                        return {'allowed': False, 'reason': 'Device not trusted'}
                
                # 2. Check business hours requirement
                if rule.require_business_hours:
                    current_time = datetime.now().time()
                    start_time = rule.allowed_start_time
                    end_time = rule.allowed_end_time
                    
                    if start_time and end_time:
                        if not (start_time <= current_time <= end_time):
                            return {'allowed': False, 'reason': 'Outside business hours'}
                
                # 3. Check IP whitelist
                if rule.allowed_ip_ranges:
                    ip = context.get('ip_address', '')
                    if ip and not AccessControlService.check_ip_range(ip, rule.allowed_ip_ranges):
                        return {'allowed': False, 'reason': 'IP not whitelisted'}
                
                # ✅ ALL CHECKS PASSED
                return {'allowed': True, 'reason': 'Access granted'}
        
        return {'allowed': False, 'reason': 'Access denied by policy'}
    
    @staticmethod
    def check_ip_range(ip, allowed_ranges):
        """Check if IP is in allowed ranges"""
        try:
            import json
            if isinstance(allowed_ranges, str):
                allowed_ranges = json.loads(allowed_ranges)
            
            for range_item in allowed_ranges:
                if ip.startswith(range_item.split('/')[0]):
                    return True
            return False
        except:
            return True

def require_role(*allowed_roles):
    """Decorator to check user role"""
    def decorator(f):
        from functools import wraps
        from flask import redirect, url_for, flash
        from flask_login import current_user
        
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Please login first', 'error')
                return redirect(url_for('login'))
            
            # ✅ SUPER ADMIN ALWAYS ALLOWED
            if current_user.is_super_admin:
                return f(*args, **kwargs)
            
            user_role = current_user.role
            
            if user_role not in allowed_roles:
                flash(f'❌ Access Denied: {user_role.upper()} role required', 'error')
                logger.warning('Access denied for %s to %s', current_user.username, f.__name__)
                return redirect(url_for('dashboard'))
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

def require_resource(resource, action):
    """Decorator to check resource access"""
    def decorator(f):
        from functools import wraps
        from flask import redirect, url_for, flash, request
        from flask_login import current_user
        
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Please login first', 'error')
                return redirect(url_for('login'))
            
            # ✅ SUPER ADMIN ALWAYS ALLOWED
            if current_user.is_super_admin:
                return f(*args, **kwargs)
            
            context = {
                'ip_address': request.remote_addr,
                'device_fingerprint': request.headers.get('User-Agent', ''),
                'is_trusted_device': True,
                'timestamp': datetime.now(timezone.utc)
            }
            
            access_check = AccessControlService.evaluate_access(
                current_user,
                resource,
                action,
                context
            )
            
            if not access_check['allowed']:
                flash(f"❌ Access Denied: {access_check['reason']}", 'error')
                logger.warning('Resource access denied for %s: %s', current_user.username, resource)
                return redirect(url_for('dashboard'))
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator
