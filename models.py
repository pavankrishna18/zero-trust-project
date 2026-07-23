"""
ZeroTrustX - Database Models
✅ FULLY ENHANCED WITH ALL ZTNA FEATURES - RELATIONSHIP ERRORS FIXED
Complete database schema with:
- Risk-based authentication
- Geo-location tracking
- Threat intelligence
- Rate limiting
- Enhanced security features
UPDATED & FIXED - November 8, 2025
"""

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone, timedelta
import pyotp
import json

db = SQLAlchemy()

# ==================== USER MODEL (ENHANCED & FIXED) ====================

class User(UserMixin, db.Model):
    """User model with authentication and permission management"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    
    # Role and Permissions
    role = db.Column(db.String(20), default='user', nullable=False, index=True)
    is_super_admin = db.Column(db.Boolean, default=False, nullable=False)
    department = db.Column(db.String(100), default='General', nullable=False)
    
    # Authentication
    otp_secret = db.Column(db.String(32), nullable=True)
    is_mfa_enabled = db.Column(db.Boolean, default=True, nullable=False)
    
    # Account Status
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_locked = db.Column(db.Boolean, default=False, nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)
    
    # ✅ NEW: Enhanced Password Security
    password_changed_at = db.Column(db.DateTime, nullable=True)
    password_expires_at = db.Column(db.DateTime, nullable=True)
    require_password_change = db.Column(db.Boolean, default=False)
    password_history = db.Column(db.Text, nullable=True)
    
    # ✅ NEW: User Preferences
    timezone = db.Column(db.String(50), default='UTC')
    language = db.Column(db.String(10), default='en')
    notification_preferences = db.Column(db.Text, nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)
    last_activity = db.Column(db.DateTime, nullable=True)
    last_password_change = db.Column(db.DateTime, nullable=True)
    
    # ✅ FIXED: Relationships with explicit foreign_keys
    devices = db.relationship('Device', 
                             foreign_keys='Device.user_id',
                             backref='user', 
                             lazy='dynamic', 
                             cascade='all, delete-orphan')
    
    sessions = db.relationship('Session', 
                              backref='user', 
                              lazy='dynamic', 
                              cascade='all, delete-orphan')
    
    activities = db.relationship('ActivityLog', 
                                backref='user', 
                                lazy='dynamic', 
                                cascade='all, delete-orphan')
    
    added_ips = db.relationship('IPWhitelist', 
                               foreign_keys='IPWhitelist.added_by',
                               backref='added_by_user', 
                               lazy='dynamic')
    
    risk_assessments = db.relationship('RiskAssessment', 
                                      backref='user', 
                                      lazy='dynamic', 
                                      cascade='all, delete-orphan')
    
    login_history = db.relationship('LoginHistory', 
                                   backref='user', 
                                   lazy='dynamic', 
                                   cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    # ==================== AUTHENTICATION METHODS ====================
    
    def set_password(self, password):
        """Hash and set password with expiration"""
        self.password_hash = generate_password_hash(password)
        self.password_changed_at = datetime.now(timezone.utc)
        self.last_password_change = datetime.now(timezone.utc)
        self.password_expires_at = datetime.now(timezone.utc) + timedelta(days=90)
    
    def check_password(self, password):
        """Verify password"""
        return check_password_hash(self.password_hash, password)
    
    def generate_otp_secret(self):
        """Generate OTP secret for 2FA"""
        self.otp_secret = pyotp.random_base32()
        return self.otp_secret
    
    def verify_otp(self, token):
        """Verify OTP token"""
        if not self.otp_secret:
            return False
        totp = pyotp.TOTP(self.otp_secret)
        return totp.verify(token, valid_window=1)
    
    def get_otp_uri(self):
        """Get OTP URI for QR code"""
        if not self.otp_secret:
            return None
        totp = pyotp.TOTP(self.otp_secret)
        return totp.provisioning_uri(name=self.email, issuer_name='ZeroTrustX')
    
    # ==================== ACCOUNT MANAGEMENT ====================
    
    def lock_account(self, duration_minutes=30):
        """Lock account temporarily"""
        self.is_locked = True
        self.locked_until = datetime.now(timezone.utc) + timedelta(minutes=duration_minutes)
        db.session.commit()
    
    def unlock_account(self):
        """Unlock account"""
        self.is_locked = False
        self.locked_until = None
        self.failed_login_attempts = 0
        db.session.commit()
    
    def increment_failed_login_attempts(self):
        """Increment failed login attempts"""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            self.lock_account()
        db.session.commit()
    
    def reset_failed_login_attempts(self):
        """Reset failed login attempts"""
        self.failed_login_attempts = 0
        self.last_login = datetime.now(timezone.utc)
        self.last_activity = datetime.now(timezone.utc)
        db.session.commit()
    
    def is_account_locked(self):
        """Check if account is locked"""
        if not self.is_locked:
            return False
        
        if self.locked_until and datetime.now(timezone.utc) > self.locked_until:
            self.unlock_account()
            return False
        
        return self.is_locked
    
    # ==================== PERMISSION METHODS ====================
    
    def get_permissions(self):
        from permissions import get_user_permissions
        return get_user_permissions(self)
    
    def has_permission(self, permission):
        from permissions import has_permission
        return has_permission(self, permission)
    
    def can_create_users(self):
        return self.has_permission('can_create_users')
    
    def can_edit_users(self):
        return self.has_permission('can_edit_users')
    
    def can_delete_users(self):
        return self.has_permission('can_delete_users')
    
    def can_change_roles(self):
        return self.has_permission('can_change_roles')
    
    def can_unlock_accounts(self):
        return self.has_permission('can_unlock_accounts')
    
    def can_create_rules(self):
        return self.has_permission('can_create_rules')
    
    def can_approve_devices(self):
        return self.has_permission('can_approve_devices')
    
    def can_revoke_devices(self):
        return self.has_permission('can_revoke_devices')
    
    def can_terminate_sessions(self):
        return self.has_permission('can_terminate_sessions')
    
    def can_view_all_activities(self):
        return self.has_permission('can_view_all_activities')
    
    def can_view_all_users(self):
        return self.has_permission('can_view_all_users')
    
    def can_view_metrics(self):
        return self.has_permission('can_view_metrics')
    
    def can_access_admin_dashboard(self):
        return self.has_permission('can_access_admin_dashboard')
    
    def can_access_sensitive_data(self):
        return self.has_permission('can_access_sensitive_data')
    
    # ==================== ROLE INFORMATION ====================
    
    def get_role_display(self):
        """Get role display name with icon"""
        role_map = {
            'super_admin': '👑 Super Admin',
            'admin': '🛡️ Admin',
            'manager': '📊 Manager',
            'user': '👥 User',
            'guest': '🔍 Guest'
        }
        
        if self.is_super_admin:
            return role_map['super_admin']
        return role_map.get(self.role, 'Unknown')
    
    def to_dict(self):
        """Convert user to dictionary"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'is_super_admin': self.is_super_admin,
            'department': self.department,
            'is_active': self.is_active,
            'is_locked': self.is_locked,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
        }


# ==================== DEVICE MODEL (ENHANCED & FIXED) ====================

class Device(db.Model):
    """Trusted device model"""
    __tablename__ = 'devices'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    
    device_name = db.Column(db.String(255), nullable=False)
    device_fingerprint = db.Column(db.String(512), unique=True, nullable=False, index=True)
    ip_address = db.Column(db.String(50), nullable=False)
    browser = db.Column(db.String(255), nullable=False)
    os = db.Column(db.String(255), nullable=False)
    user_agent = db.Column(db.Text, nullable=False)
    
    is_trusted = db.Column(db.Boolean, default=False, nullable=False, index=True)
    trust_score = db.Column(db.Float, default=0.0, nullable=False)
    
    # ✅ Device Security
    is_compromised = db.Column(db.Boolean, default=False)
    compromised_at = db.Column(db.DateTime, nullable=True)
    last_security_scan = db.Column(db.DateTime, nullable=True)
    security_score = db.Column(db.Integer, default=100)
    device_type = db.Column(db.String(20))
    
    # ✅ Trust Management - FIXED: Removed trust_granted_by to avoid multiple FK paths
    trust_granted_at = db.Column(db.DateTime, nullable=True)
    trust_expires_at = db.Column(db.DateTime, nullable=True)
    
    last_used = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    
    def __repr__(self):
        return f'<Device {self.device_name}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'device_name': self.device_name,
            'ip_address': self.ip_address,
            'browser': self.browser,
            'os': self.os,
            'is_trusted': self.is_trusted,
            'security_score': self.security_score,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


# ==================== SESSION MODEL (ENHANCED) ====================

class Session(db.Model):
    """Active user session model"""
    __tablename__ = 'sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    
    session_token = db.Column(db.String(512), unique=True, nullable=False, index=True)
    device_fingerprint = db.Column(db.String(512), nullable=False)
    ip_address = db.Column(db.String(50), nullable=False)
    user_agent = db.Column(db.Text, nullable=False)
    
    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    
    # ✅ Session Security
    risk_score = db.Column(db.Integer, default=0)
    is_suspicious = db.Column(db.Boolean, default=False)
    location_country = db.Column(db.String(2))
    location_city = db.Column(db.String(100))
    jwt_token = db.Column(db.Text, nullable=True)
    
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    ended_at = db.Column(db.DateTime, nullable=True)
    last_activity = db.Column(db.DateTime, nullable=True)
    # ✅ Phase 7: timestamp of the last full continuous-verification pass,
    # used to throttle re-evaluation frequency (see zero_trust_engine.py)
    last_zt_check = db.Column(db.DateTime, nullable=True)
    
    def __repr__(self):
        return f'<Session {self.id}>'
    
    def is_expired(self):
        return datetime.now(timezone.utc) > self.expires_at
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.user.username if self.user else 'Unknown',
            'ip_address': self.ip_address,
            'location': f"{self.location_city}, {self.location_country}" if self.location_city else self.ip_address,
            'risk_score': self.risk_score,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None,
            'is_active': self.is_active,
        }


# ==================== ACCESS RULE MODEL (ENHANCED) ====================

class AccessRule(db.Model):
    """Access control rules"""
    __tablename__ = 'access_rules'
    
    id = db.Column(db.Integer, primary_key=True)
    
    name = db.Column(db.String(255), nullable=False, index=True)
    description = db.Column(db.Text, nullable=True)
    role = db.Column(db.String(50), nullable=False, index=True)
    resource = db.Column(db.String(255), nullable=False, index=True)
    action = db.Column(db.String(50), nullable=False)
    
    require_trusted_device = db.Column(db.Boolean, default=False, nullable=False)
    require_business_hours = db.Column(db.Boolean, default=False, nullable=False)
    allowed_start_time = db.Column(db.String(5), nullable=True)
    allowed_end_time = db.Column(db.String(5), nullable=True)
    max_sessions = db.Column(db.Integer, default=1, nullable=False)
    allowed_ip_ranges = db.Column(db.Text, nullable=True)
    allowed_days = db.Column(db.Text, nullable=True)
    
    # ✅ Advanced Conditions
    require_mfa = db.Column(db.Boolean, default=True)
    max_risk_score = db.Column(db.Integer, default=70)
    require_geo_restrictions = db.Column(db.Boolean, default=False)
    allowed_countries = db.Column(db.Text, nullable=True)
    priority = db.Column(db.Integer, default=0)
    
    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    def __repr__(self):
        return f'<AccessRule {self.name}>'
    
    def get_allowed_days(self):
        if not self.allowed_days:
            return []
        try:
            return json.loads(self.allowed_days)
        except:
            return []
    
    def get_allowed_ip_ranges(self):
        if not self.allowed_ip_ranges:
            return []
        try:
            return json.loads(self.allowed_ip_ranges)
        except:
            return []
    
    def get_allowed_countries(self):
        if not self.allowed_countries:
            return []
        try:
            return json.loads(self.allowed_countries)
        except:
            return []
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'role': self.role,
            'resource': self.resource,
            'action': self.action,
            'require_trusted_device': self.require_trusted_device,
            'require_mfa': self.require_mfa,
            'max_risk_score': self.max_risk_score,
            'is_active': self.is_active,
        }


# ==================== ACTIVITY LOG MODEL (ENHANCED) ====================

class ActivityLog(db.Model):
    """Audit log"""
    __tablename__ = 'activity_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    username = db.Column(db.String(80), nullable=False, index=True)
    
    action = db.Column(db.String(255), nullable=False, index=True)
    status = db.Column(db.String(50), nullable=False, index=True)
    details = db.Column(db.Text, nullable=True)
    
    ip_address = db.Column(db.String(50), nullable=True, index=True)
    user_agent = db.Column(db.Text, nullable=True)
    resource_accessed = db.Column(db.String(255), nullable=True, index=True)
    
    # ✅ Enhanced Tracking
    risk_score = db.Column(db.Integer, nullable=True)
    location_country = db.Column(db.String(2))
    location_city = db.Column(db.String(100))
    is_suspicious = db.Column(db.Boolean, default=False, index=True)
    threat_level = db.Column(db.String(20))
    
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    
    __table_args__ = (
        db.Index('idx_user_timestamp', 'user_id', 'timestamp'),
        db.Index('idx_action_timestamp', 'action', 'timestamp'),
        db.Index('idx_suspicious', 'is_suspicious', 'timestamp'),
    )
    
    def __repr__(self):
        return f'<ActivityLog {self.action}>'
    
    @staticmethod
    def log_activity(user_id, username, action, status, details, ip_address=None, user_agent=None, resource_accessed=None):
        """Create activity log entry"""
        log = ActivityLog(
            user_id=user_id,
            username=username,
            action=action,
            status=status,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent,
            resource_accessed=resource_accessed,
            timestamp=datetime.now(timezone.utc)
        )
        db.session.add(log)
        db.session.commit()
        return log
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'action': self.action,
            'status': self.status,
            'details': self.details,
            'location': f"{self.location_city}, {self.location_country}" if self.location_city else self.ip_address,
            'risk_score': self.risk_score,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S') if self.timestamp else None,
        }


# ==================== IP WHITELIST MODEL ====================

class IPWhitelist(db.Model):
    """IP Whitelist Model"""
    __tablename__ = 'ip_whitelist'
    
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), nullable=False, unique=True, index=True)
    description = db.Column(db.String(200), nullable=True)
    
    added_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    added_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    
    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    is_range = db.Column(db.Boolean, default=False, nullable=False)
    
    # ✅ Auto-blocking
    is_auto_blocked = db.Column(db.Boolean, default=False)
    block_reason = db.Column(db.String(200), nullable=True)
    blocked_at = db.Column(db.DateTime, nullable=True)
    
    # ✅ Usage tracking
    last_used = db.Column(db.DateTime, nullable=True)
    usage_count = db.Column(db.Integer, default=0)
    expires_at = db.Column(db.DateTime, nullable=True)
    
    def __repr__(self):
        return f'<IPWhitelist {self.ip_address}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'description': self.description,
            'added_by': self.added_by_user.username if self.added_by_user else 'System',
            'added_at': self.added_at.strftime('%Y-%m-%d %H:%M:%S') if self.added_at else None,
            'is_active': self.is_active,
            'is_range': self.is_range,
            'usage_count': self.usage_count,
        }
    
    @staticmethod
    def is_ip_whitelisted(ip_address):
        """Check if IP is whitelisted"""
        import ipaddress as ip_lib
        
        try:
            user_ip = ip_lib.ip_address(ip_address)
            active_ips = IPWhitelist.query.filter_by(is_active=True).all()
            
            for entry in active_ips:
                try:
                    if entry.is_range:
                        network = ip_lib.ip_network(entry.ip_address, strict=False)
                        if user_ip in network:
                            entry.last_used = datetime.now(timezone.utc)
                            entry.usage_count += 1
                            db.session.commit()
                            return True
                    else:
                        if str(user_ip) == entry.ip_address:
                            entry.last_used = datetime.now(timezone.utc)
                            entry.usage_count += 1
                            db.session.commit()
                            return True
                except:
                    continue
            
            return False
        except:
            return False
    
    @staticmethod
    def add_default_ips():
        """Add default IPs"""
        try:
            localhost = IPWhitelist.query.filter_by(ip_address='127.0.0.1').first()
            
            if not localhost:
                default_ips = [
                    IPWhitelist(ip_address='127.0.0.1', description='Localhost', is_active=True, is_range=False),
                    IPWhitelist(ip_address='::1', description='IPv6 Localhost', is_active=True, is_range=False)
                ]
                
                for ip_entry in default_ips:
                    db.session.add(ip_entry)
                
                db.session.commit()
                return True
            return False
        except Exception as e:
            print(f'Error adding default IPs: {e}')
            db.session.rollback()
            return False


# ==================== ✅ NEW ENHANCED MODELS ====================

class RiskAssessment(db.Model):
    """Risk assessment records"""
    __tablename__ = 'risk_assessments'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    
    risk_score = db.Column(db.Integer, nullable=False, index=True)
    risk_level = db.Column(db.String(20), nullable=False, index=True)
    risk_factors = db.Column(db.Text)
    
    action = db.Column(db.String(50), nullable=False)
    ip_address = db.Column(db.String(45))
    location_country = db.Column(db.String(2))
    location_city = db.Column(db.String(100))
    
    additional_verification_required = db.Column(db.Boolean, default=False)
    was_blocked = db.Column(db.Boolean, default=False)
    admin_notified = db.Column(db.Boolean, default=False)
    
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    
    def __repr__(self):
        return f'<RiskAssessment User={self.user_id} Score={self.risk_score}>'


class LoginHistory(db.Model):
    """Login history with geo-location"""
    __tablename__ = 'login_history'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    
    ip_address = db.Column(db.String(45), nullable=False, index=True)
    user_agent = db.Column(db.Text)
    device_fingerprint = db.Column(db.String(256))
    
    country = db.Column(db.String(100))
    country_code = db.Column(db.String(2), index=True)
    city = db.Column(db.String(100))
    region = db.Column(db.String(100))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    isp = db.Column(db.String(200))
    is_proxy = db.Column(db.Boolean, default=False)
    is_hosting = db.Column(db.Boolean, default=False)
    
    success = db.Column(db.Boolean, nullable=False, index=True)
    failure_reason = db.Column(db.String(200))
    risk_score = db.Column(db.Integer)
    
    is_suspicious = db.Column(db.Boolean, default=False, index=True)
    is_impossible_travel = db.Column(db.Boolean, default=False)
    is_blocked_country = db.Column(db.Boolean, default=False)
    
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    
    def __repr__(self):
        return f'<LoginHistory User={self.user_id} IP={self.ip_address}>'


class ThreatEvent(db.Model):
    """Security threat events"""
    __tablename__ = 'threat_events'
    
    id = db.Column(db.Integer, primary_key=True)
    
    threat_type = db.Column(db.String(50), nullable=False, index=True)
    severity = db.Column(db.String(20), nullable=False, index=True)
    description = db.Column(db.Text)
    
    source_ip = db.Column(db.String(45), index=True)
    source_country = db.Column(db.String(2))
    target_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), index=True)
    target_username = db.Column(db.String(80))
    
    was_blocked = db.Column(db.Boolean, default=False)
    auto_blocked = db.Column(db.Boolean, default=False)
    admin_notified = db.Column(db.Boolean, default=False)
    response_action = db.Column(db.String(100))
    
    is_investigated = db.Column(db.Boolean, default=False)
    investigated_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    investigation_notes = db.Column(db.Text)
    is_false_positive = db.Column(db.Boolean, default=False)
    
    detected_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    resolved_at = db.Column(db.DateTime)
    
    def __repr__(self):
        return f'<ThreatEvent {self.threat_type}>'


class AIThreatAnalysis(db.Model):
    """
    Stores AI threat analysis results (Phase 6).
    Caches the output of the Log -> Risk Engine -> LLM -> Decision pipeline
    so repeat views of the same device/IP are instant and auditable.
    """
    __tablename__ = 'ai_threat_analysis'

    id = db.Column(db.Integer, primary_key=True)

    target_type = db.Column(db.String(20), nullable=False, index=True)  # 'device' | 'ip'
    target_id = db.Column(db.Integer, nullable=False, index=True)

    risk_score = db.Column(db.Integer, nullable=False)
    risk_level = db.Column(db.String(20), nullable=False)
    reasons = db.Column(db.Text)            # JSON-encoded list[str]
    mitre_attack = db.Column(db.Text)       # JSON-encoded list[{id, name}]
    recommendation = db.Column(db.String(20))
    recommendation_label = db.Column(db.String(50))
    confidence = db.Column(db.Integer, default=60)

    source = db.Column(db.String(80))       # e.g. 'groq:llama-3.2-11b' or 'rule_based'
    is_llm_generated = db.Column(db.Boolean, default=False)

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    def to_dict(self):
        return {
            'risk_score': self.risk_score,
            'risk_level': self.risk_level,
            'reasons': json.loads(self.reasons) if self.reasons else [],
            'mitre': json.loads(self.mitre_attack) if self.mitre_attack else [],
            'recommendation': self.recommendation,
            'recommendation_label': self.recommendation_label,
            'confidence': self.confidence,
            'source': self.source,
            'is_llm_generated': self.is_llm_generated,
            'analyzed_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None,
        }

    def __repr__(self):
        return f'<AIThreatAnalysis {self.target_type}:{self.target_id} {self.risk_level}>'


class GeoLocationCache(db.Model):
    """Geo-location cache"""
    __tablename__ = 'geolocation_cache'
    
    id = db.Column(db.Integer, primary_key=True)
    
    ip_address = db.Column(db.String(45), unique=True, nullable=False, index=True)
    country = db.Column(db.String(100))
    country_code = db.Column(db.String(2), index=True)
    city = db.Column(db.String(100))
    region = db.Column(db.String(100))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    isp = db.Column(db.String(200))
    
    is_proxy = db.Column(db.Boolean, default=False)
    is_hosting = db.Column(db.Boolean, default=False)
    is_vpn = db.Column(db.Boolean, default=False)
    
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime)
    lookup_count = db.Column(db.Integer, default=0)
    
    def __repr__(self):
        return f'<GeoLocationCache {self.ip_address}>'


# ==================== DATABASE INITIALIZATION ====================

def init_db(app):
    """Initialize database"""
    with app.app_context():
        try:
            db.create_all()
            IPWhitelist.add_default_ips()
            print('✅ Database initialized successfully')
            return True
        except Exception as e:
            print(f'❌ Database initialization failed: {e}')
            return False


# ==================== EXPORTS ====================

__all__ = [
    'db',
    'User',
    'Device',
    'Session',
    'AccessRule',
    'ActivityLog',
    'IPWhitelist',
    'RiskAssessment',
    'LoginHistory',
    'ThreatEvent',
    'GeoLocationCache',
    'AIThreatAnalysis',
    'init_db',
]
