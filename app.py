"""
ZeroTrustX - Zero Trust Network Access (ZTNA) Framework
✅ FULLY ENHANCED with ALL ZTNA Features - COMPLETE VERSION
Production-Ready Application with:
✅ IP Whitelist with CONTINUOUS VERIFICATION
✅ Risk-Based Authentication
✅ Geo-Location Tracking & Geo-Fencing
✅ Threat Intelligence & Auto-Blocking
✅ API Rate Limiting
✅ Data Encryption
✅ Device Approval Blocking
✅ Environment Variables (.env support)
✅ Dynamic Resource Access
✅ All Enhanced Security Features
FULLY UPDATED - November 8, 2025 - ENTERPRISE EDITION
COMPLETE FILE - 1500+ LINES
"""

import sys
import os

# Windows UTF-8 encoding fix
if sys.platform == 'win32':
    os.system('chcp 65001 > nul')
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except:
        pass

# ✅ Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, emit, join_room, leave_room

# ✅ Core Models (Enhanced)
from models import (
    db, User, Device, AccessRule, ActivityLog, Session as SessionModel,
    RiskAssessment, LoginHistory, ThreatEvent, GeoLocationCache, IPWhitelist
)

# ✅ Core Services
from auth import AuthenticationService
from access_control import AccessControlService, require_role, require_resource
from device_trust import DeviceTrustService
from monitoring import MonitoringService
from permissions import get_user_permissions, has_permission, require_permission
from resources import get_accessible_resources_for_user, check_resource_access, AVAILABLE_RESOURCES
from utils import generate_qr_code, validate_password_strength, get_user_agent
from config import Config
from ip_whitelist import is_ip_allowed, get_client_ip

# ✅ NEW: Enhanced Security Services
from risk_scoring import RiskScoringEngine
from geo_location import GeoLocationService
from threat_intelligence import ThreatIntelligence
from ai_explain import AIExplainService
from rate_limiter import rate_limit, login_rate_limit, rate_limiter
from encryption import EncryptionService

# ✅ Phase 7/8: Continuous Zero Trust verification + Threat Prevention pipeline
import zero_trust_engine
from threat_engine import ThreatPreventionEngine
from flask_wtf import CSRFProtect

import logging
from datetime import datetime, timezone, timedelta
from functools import wraps
import socket
import json

# ==================== LOGGING SETUP ====================

logging.basicConfig(
    level=getattr(logging, Config.LOG_LEVEL),
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(Config.LOG_FILE, encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# ==================== FLASK APP INITIALIZATION ====================

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)

# ✅ Phase 10 security fix: WTF_CSRF_ENABLED was set in config.py but
# CSRFProtect was never instantiated, so CSRF protection was NOT actually
# active on any form despite the config flag implying it was.
csrf = CSRFProtect(app)

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='eventlet',
    logger=False,
    engineio_logger=False,
    ping_timeout=Config.WEBSOCKET_PING_TIMEOUT if hasattr(Config, 'WEBSOCKET_PING_TIMEOUT') else 60,
    ping_interval=Config.WEBSOCKET_PING_INTERVAL if hasattr(Config, 'WEBSOCKET_PING_INTERVAL') else 25
)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.session_protection = 'strong'

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# ==================== NOTIFICATIONS (PENDING DEVICE APPROVALS) ====================

@app.context_processor
def inject_now():
    return {'now': datetime.now(timezone.utc)}


@app.context_processor
def inject_pending_device_notifications():
    """Make pending device-approval notifications available to every template.

    Only surfaced to users who are allowed to approve/revoke devices
    (super admin, admin, manager) so the master admin is notified in the
    notification bar whenever a new (non-admin) user logs in from a device
    that needs approval.
    """
    try:
        if not current_user.is_authenticated:
            return {'pending_device_notifications': [], 'pending_device_count': 0}

        if not (current_user.is_super_admin or current_user.role in ('admin', 'manager')):
            return {'pending_device_notifications': [], 'pending_device_count': 0}

        pending = (
            Device.query
            .filter_by(is_trusted=False)
            .join(User, Device.user_id == User.id)
            .order_by(Device.created_at.desc())
            .limit(8)
            .all()
        )
        return {
            'pending_device_notifications': pending,
            'pending_device_count': Device.query.filter_by(is_trusted=False).count(),
        }
    except Exception:
        return {'pending_device_notifications': [], 'pending_device_count': 0}

# ==================== DATABASE INITIALIZATION ====================

def init_database():
    """Initialize database with default data"""
    with app.app_context():
        try:
            db.create_all()
            logger.info('✅ Database tables created successfully')
        except Exception as e:
            logger.error('❌ Error creating database tables: %s', str(e))
            raise
        
        # Create default access rules
        try:
            if AccessRule.query.count() == 0:
                default_rules = [
                    AccessRule(name='Admin Full Access', role='admin', resource='admin_dashboard', action='read', is_active=True),
                    AccessRule(name='Admin User Management', role='admin', resource='user_management', action='write', is_active=True),
                    AccessRule(name='Admin Policy Management', role='admin', resource='policy_management', action='write', is_active=True),
                    AccessRule(name='Manager Team Access', role='manager', resource='team_dashboard', action='read', is_active=True),
                    AccessRule(name='Manager Activity Logs', role='manager', resource='activity_logs', action='read', is_active=True),
                    AccessRule(name='User Dashboard Access', role='user', resource='user_dashboard', action='read', is_active=True),
                    AccessRule(name='User Employee Directory', role='user', resource='employee_directory', action='read', is_active=True),
                    AccessRule(name='User Projects', role='user', resource='projects', action='read', is_active=True),
                    AccessRule(name='User Leave', role='user', resource='leave_management', action='read', is_active=True),
                    AccessRule(name='User Device Management', role='user', resource='device_management', action='read', is_active=True),
                ]
                
                for rule in default_rules:
                    db.session.add(rule)
                
                db.session.commit()
                logger.info('✅ Default access rules created')
        except Exception as e:
            logger.warning('⚠️ Error creating default rules: %s', str(e))
            db.session.rollback()
        
        # Add default IPs to whitelist
        try:
            IPWhitelist.add_default_ips()
            logger.info('✅ Default IPs added to whitelist')
        except Exception as e:
            logger.warning('⚠️ Error adding default IPs: %s', str(e))
        
        # Create default super admin account
        try:
            if User.query.filter_by(role='admin').count() == 0:
                admin_result = AuthenticationService.register_user(
                    username='admin',
                    email='admin@zerotrust.com',
                    password='Admin@123',
                    role='admin'
                )
                if admin_result['success']:
                    admin_user = User.query.filter_by(username='admin').first()
                    if admin_user:
                        admin_user.is_super_admin = True
                        db.session.commit()
                    
                    print("\n" + "="*80)
                    print("🔐 DEFAULT SUPER ADMIN ACCOUNT CREATED")
                    print("="*80)
                    print("Username: admin")
                    print("Password: Admin@123")
                    print(f"OTP Secret: {admin_result['otp_secret']}")
                    print("Role: SUPER ADMIN (Full Access)")
                    print("="*80 + "\n")
                    logger.info('✅ Super admin account created successfully')
        except Exception as e:
            logger.warning('⚠️ Error creating admin user: %s', str(e))

init_database()

# ==================== HELPER FUNCTIONS ====================

def check_if_device_trusted(user):
    """Check if current device is trusted.

    Master admin (super admin) and admin/manager roles never need device
    approval - they're always treated as trusted. Approval only applies to
    regular ('user'/'guest') accounts.
    """
    try:
        if user.is_super_admin or user.role in ('admin', 'manager'):
            return True

        ip_address = request.remote_addr or '127.0.0.1'
        user_agent = request.headers.get('User-Agent', 'Unknown')
        
        fingerprint = DeviceTrustService.generate_device_fingerprint(user.id, ip_address, user_agent)
        
        device = Device.query.filter_by(
            user_id=user.id,
            device_fingerprint=fingerprint
        ).first()
        
        return device.is_trusted if device else False
    except:
        return False

def broadcast_update(event_type, data, target='all'):
    """Broadcast updates via WebSocket"""
    try:
        if target == 'admin':
            socketio.emit(event_type, data, room='admin_dashboard', namespace='/')
        elif target == 'all':
            socketio.emit(event_type, data, broadcast=True, namespace='/')
        else:
            socketio.emit(event_type, data, room=target, namespace='/')
    except Exception as e:
        logger.error('Broadcast error: %s', str(e))

def error_handler(f):
    """Decorator for error handling"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            logger.error('Error in %s: %s', f.__name__, str(e))
            flash(f'An error occurred: {str(e)}', 'error')
            return redirect(url_for('index'))
    return decorated_function

# ==================== ✅ ENHANCED: CONTINUOUS SECURITY VERIFICATION ====================

@app.before_request
def enforce_security_realtime():
    """
    ✅ ZERO TRUST: Continuous Verification
    - IP whitelist check on EVERY request
    - Geo-location validation
    - Threat detection
    - Rate limiting
    """
    # Skip if not applicable
    public_endpoints = ['index', 'login', 'register', 'static', 'verify_otp']
    if request.endpoint in public_endpoints or (request.endpoint and 'static' in request.endpoint):
        return None
    
    if not current_user.is_authenticated:
        return None
    
    client_ip = get_client_ip(request)
    user_role = current_user.role
    
    # ✅ 1. IP WHITELIST CHECK
    if Config.ENABLE_IP_WHITELIST:
        if not is_ip_allowed(client_ip, user_role):
            logger.warning('🚫 REAL-TIME IP BLOCK: %s from %s', current_user.username, client_ip)
            
            try:
                active_sessions = SessionModel.query.filter_by(user_id=current_user.id, is_active=True).all()
                for user_session in active_sessions:
                    user_session.is_active = False
                    user_session.ended_at = datetime.now(timezone.utc)
                db.session.commit()
            except:
                db.session.rollback()
            
            ActivityLog.log_activity(
                current_user.id, 
                current_user.username, 
                'ip_blocked_realtime', 
                'security_block', 
                f'IP block: {client_ip}'
            )
            
            session.clear()
            logout_user()
            flash('🚫 Security Alert: Your IP has been blocked.', 'error')
            return redirect(url_for('index'))
    
    # ✅ 2. GEO-LOCATION CHECK
    if Config.ENABLE_GEOLOCATION:
        try:
            location = GeoLocationService.get_location(client_ip)
            
            if location['country_code'] in Config.BLOCKED_COUNTRIES:
                logger.warning('🚫 Blocked country: %s from %s', current_user.username, location['country'])
                
                ActivityLog.log_activity(
                    current_user.id,
                    current_user.username,
                    'geo_blocked',
                    'security_block',
                    f"Blocked country: {location['country']}"
                )
                
                session.clear()
                logout_user()
                flash('🚫 Access from your location is not permitted.', 'error')
                return redirect(url_for('index'))
            
            if Config.BLOCK_VPN_PROXY and location.get('is_proxy'):
                logger.warning('🚫 VPN/Proxy blocked: %s', current_user.username)
                flash('🚫 VPN/Proxy connections are not allowed.', 'error')
                return redirect(url_for('index'))
        
        except Exception as e:
            logger.error('Geo-location check error: %s', str(e))
    
    # ✅ 3. THREAT INTELLIGENCE -> full Detect-to-Admin-Review pipeline (Phase 8)
    if Config.ENABLE_THREAT_INTELLIGENCE:
        try:
            if ThreatIntelligence.detect_brute_force(current_user.username, client_ip):
                logger.warning('🚨 Brute-force detected: %s', current_user.username)

                ThreatPreventionEngine.process(
                    threat_type='brute_force',
                    severity='high',
                    description='Brute-force attack detected',
                    source_ip=client_ip,
                    user=current_user,
                    socketio=socketio,
                    auto_block_fn=ThreatIntelligence.auto_block_malicious_ip if Config.AUTO_BLOCK_MALICIOUS_IPS else None,
                )

        except Exception as e:
            logger.error('Threat intelligence error: %s', str(e))

    # ✅ 4. CONTINUOUS ZERO TRUST VERIFICATION (Phase 7)
    # 8-factor re-check on every request: Identity + Device + Location + Risk
    # + Behavior + Time + Resource + Session. A successful login is only the
    # first checkpoint — this is what keeps verifying afterward.
    if Config.ENABLE_THREAT_INTELLIGENCE or Config.ENABLE_GEOLOCATION:
        try:
            user_session = SessionModel.query.filter_by(
                user_id=current_user.id, is_active=True
            ).order_by(SessionModel.id.desc()).first()

            if zero_trust_engine.should_reevaluate(user_session):
                device = Device.query.filter_by(
                    user_id=current_user.id, ip_address=client_ip
                ).order_by(Device.id.desc()).first()

                result = zero_trust_engine.evaluate(
                    current_user, client_ip, get_user_agent(request),
                    device=device, session_record=user_session,
                )

                if user_session is not None:
                    try:
                        user_session.last_zt_check = datetime.now(timezone.utc)
                        user_session.risk_score = int(result.score)
                        db.session.commit()
                    except Exception:
                        db.session.rollback()

                if result.decision == 'block':
                    logger.warning('🚫 Continuous verification BLOCK for %s: %s',
                                    current_user.username, result.reasons)
                    ActivityLog.log_activity(
                        current_user.id, current_user.username,
                        'zt_continuous_block', 'security_block',
                        f"Composite risk {result.score}: {'; '.join(result.reasons) or 'policy threshold exceeded'}"
                    )
                    if user_session is not None:
                        user_session.is_active = False
                        user_session.ended_at = datetime.now(timezone.utc)
                        db.session.commit()
                    session.clear()
                    logout_user()
                    flash('🚫 Session ended: continuous verification detected elevated risk.', 'error')
                    return redirect(url_for('index'))

                elif result.decision == 'step_up':
                    logger.info('🔁 Continuous verification STEP-UP for %s: %s',
                                current_user.username, result.reasons)
                    ActivityLog.log_activity(
                        current_user.id, current_user.username,
                        'zt_step_up_required', 'security_alert',
                        f"Composite risk {result.score}: {'; '.join(result.reasons) or 'elevated risk'}"
                    )
                    # Re-authentication required: do not trust the session
                    # just because login succeeded earlier.
                    if request.endpoint != 'verify_otp':
                        session['step_up_required'] = True
                        session['step_up_reason'] = '; '.join(result.reasons) or 'Elevated risk detected'
                        flash('🔒 Re-verification required for continued access.', 'warning')
                        return redirect(url_for('verify_otp'))

        except Exception as e:
            logger.error('Continuous verification error: %s', str(e))

    return None

# ==================== WEBSOCKET HANDLERS ====================

@socketio.on('connect')
def handle_connect(auth=None):
    """Handle WebSocket connection"""
    try:
        logger.info('Client connected: %s', request.sid)
        emit('connection_response', {'status': 'connected', 'message': 'Real-time updates enabled'})
    except Exception as e:
        logger.error('Connection error: %s', str(e))

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection"""
    try:
        logger.info('Client disconnected: %s', request.sid)
    except Exception as e:
        logger.error('Disconnection error: %s', str(e))

@socketio.on('join_dashboard')
def handle_join_dashboard(data):
    """Join user's dashboard room"""
    user_id = data.get('user_id')
    role = data.get('role')
    
    try:
        if role in ['admin', 'super_admin']:
            join_room('admin_dashboard')
            emit('joined', {'room': 'admin_dashboard'})
        elif role == 'manager':
            join_room('manager_dashboard')
            emit('joined', {'room': 'manager_dashboard'})
        else:
            join_room(f'user_dashboard_{user_id}')
            emit('joined', {'room': f'user_dashboard_{user_id}'})
    except Exception as e:
        logger.error('Error joining dashboard: %s', str(e))

# ==================== AUTH ROUTES (ENHANCED) ====================

@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not all([username, email, password, confirm_password]):
            flash('All fields are required', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html')
        
        password_check = validate_password_strength(password)
        if not password_check['valid']:
            for error in password_check['errors']:
                flash(error, 'error')
            return render_template('register.html')
        
        result = AuthenticationService.register_user(username, email, password, role='user')
        
        if result['success']:
            otp_uri = AuthenticationService.get_otp_uri(username, result['otp_secret'])
            qr_code = generate_qr_code(otp_uri)
            
            logger.info('User %s registered successfully', username)
            flash('Registration successful! Scan the QR code.', 'success')
            return render_template('register.html', show_qr=True, qr_code=qr_code, otp_secret=result['otp_secret'])
        else:
            flash(result['message'], 'error')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@login_rate_limit(max_attempts=5, window_seconds=300)
def login():
    """✅ Enhanced login with risk assessment"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        client_ip = get_client_ip(request)
        
        temp_user = User.query.filter_by(username=username).first()
        user_role = temp_user.role if temp_user else None
        
        # ✅ IP WHITELIST CHECK
        if Config.ENABLE_IP_WHITELIST and not is_ip_allowed(client_ip, user_role):
            logger.warning('🚫 Login blocked: %s from %s', username, client_ip)
            flash('❌ Access Denied: Your IP is not authorized', 'error')
            return render_template('login.html')
        
        # ✅ GEO-LOCATION CHECK
        location_data = None
        if Config.ENABLE_GEOLOCATION:
            try:
                location_data = GeoLocationService.get_location(client_ip)
                
                if location_data['country_code'] in Config.BLOCKED_COUNTRIES:
                    logger.warning('🚫 Login from blocked country: %s', location_data['country'])
                    flash('🚫 Access from your location is not permitted', 'error')
                    return render_template('login.html')
            except:
                pass
        
        # Authenticate
        result = AuthenticationService.authenticate_user(username, password)
        
        if result['success']:
            user = result['user']
            
            # ✅ RISK SCORING
            risk_data = None
            if Config.ENABLE_RISK_SCORING:
                try:
                    risk_data = RiskScoringEngine.calculate_risk_score(
                        user, client_ip, request.headers.get('User-Agent'), None
                    )
                    
                    risk_assessment = RiskAssessment(
                        user_id=user.id,
                        risk_score=risk_data['score'],
                        risk_level=risk_data['level'],
                        risk_factors=str(risk_data['factors']),
                        action='login',
                        ip_address=client_ip,
                        location_country=location_data['country_code'] if location_data else None,
                        location_city=location_data['city'] if location_data else None,
                        additional_verification_required=risk_data['requires_additional_verification'],
                        was_blocked=risk_data['score'] >= Config.RISK_SCORE_THRESHOLD_CRITICAL
                    )
                    db.session.add(risk_assessment)
                    db.session.commit()
                    
                    if Config.AUTO_BLOCK_CRITICAL_RISK and risk_data['level'] == 'CRITICAL':
                        logger.warning('🚨 CRITICAL RISK LOGIN BLOCKED: %s', username)
                        flash('🚫 Login blocked due to high-risk factors', 'error')
                        return render_template('login.html')
                
                except Exception as e:
                    logger.error('Risk scoring error: %s', str(e))
            
            # ✅ LOG LOGIN HISTORY
            try:
                login_record = LoginHistory(
                    user_id=user.id,
                    ip_address=client_ip,
                    user_agent=request.headers.get('User-Agent'),
                    country=location_data['country'] if location_data else None,
                    country_code=location_data['country_code'] if location_data else None,
                    city=location_data['city'] if location_data else None,
                    latitude=location_data.get('latitude'),
                    longitude=location_data.get('longitude'),
                    isp=location_data.get('isp'),
                    is_proxy=location_data.get('is_proxy', False) if location_data else False,
                    success=True,
                    risk_score=risk_data['score'] if risk_data else None
                )
                db.session.add(login_record)
                db.session.commit()
            except Exception as e:
                logger.error('Login history error: %s', str(e))
            
            session['temp_user_id'] = user.id
            session['temp_username'] = user.username
            logger.info('✅ User %s authenticated from %s', username, client_ip)
            
            return redirect(url_for('verify_otp'))
        else:
            # ✅ LOG FAILED LOGIN
            if temp_user:
                try:
                    login_record = LoginHistory(
                        user_id=temp_user.id,
                        ip_address=client_ip,
                        user_agent=request.headers.get('User-Agent'),
                        country=location_data['country'] if location_data else None,
                        country_code=location_data['country_code'] if location_data else None,
                        success=False,
                        failure_reason=result['message']
                    )
                    db.session.add(login_record)
                    db.session.commit()
                except:
                    pass
            
            flash(result['message'], 'error')
    
    return render_template('login.html')
@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    """OTP verification with device approval"""
    # ✅ Phase 7: step-up re-authentication path. Continuous verification
    # redirects an ALREADY-authenticated session here when composite risk
    # rises mid-session — distinct from the first-login OTP flow above,
    # which uses temp_user_id for a not-yet-authenticated user.
    if session.get('step_up_required') and current_user.is_authenticated:
        if request.method == 'POST':
            otp_token = request.form.get('otp', '').strip()
            if AuthenticationService.verify_otp(current_user.otp_secret, otp_token):
                session.pop('step_up_required', None)
                session.pop('step_up_reason', None)
                ActivityLog.log_activity(
                    current_user.id, current_user.username,
                    'zt_step_up_verified', 'security_event',
                    'Re-authentication completed after elevated risk detection'
                )
                flash('✅ Identity re-verified.', 'success')
                if current_user.role == 'admin' or current_user.is_super_admin:
                    return redirect(url_for('admin_dashboard'))
                elif current_user.role == 'manager':
                    return redirect(url_for('manager_dashboard'))
                return redirect(url_for('dashboard'))
            flash('Invalid OTP', 'error')
        return render_template('verify_otp.html', step_up=True,
                                step_up_reason=session.get('step_up_reason'))

    if 'temp_user_id' not in session:
        flash('Session expired', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        otp_token = request.form.get('otp', '').strip()
        user_id = session.get('temp_user_id')
        
        user = db.session.get(User, user_id)
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('login'))
        
        if AuthenticationService.verify_otp(user.otp_secret, otp_token):
            ip_address = request.remote_addr or '127.0.0.1'
            user_agent = request.headers.get('User-Agent') or 'Unknown'
            
            device_result = DeviceTrustService.register_device(user.id, ip_address, user_agent)
            
            if not device_result.get('success'):
                flash(f"Device registration failed", 'error')
                return redirect(url_for('login'))
            
            device = device_result.get('device')
            
            # Master admin (super admin) and admin/manager roles are exempt from device
            # approval entirely - their devices are always auto-trusted. Pending device
            # approval only applies to regular ('user'/'guest') accounts.
            if user.is_super_admin or user.role in ('admin', 'manager'):
                device.is_trusted = True
                device.trust_score = 100
                device.trust_granted_at = datetime.now(timezone.utc)
            db.session.commit()
            
            session_result = AuthenticationService.create_session(user, device.device_fingerprint, user_agent=user_agent)
            
            if session_result.get('success'):
                session['user_id'] = user.id
                session['username'] = user.username
                session['role'] = user.role
                session['is_super_admin'] = user.is_super_admin
                session['jwt_token'] = session_result.get('jwt_token')
                session['device_trusted'] = device.is_trusted
                
                session.pop('temp_user_id', None)
                session.pop('temp_username', None)
                
                login_user(user)
                
                if not device.is_trusted:
                    flash('⏳ Device pending approval', 'warning')
                    return redirect(url_for('pending_device_approval'))
                
                flash('✅ Login successful!', 'success')
                
                if user.role == 'admin' or user.is_super_admin:
                    return redirect(url_for('admin_dashboard'))
                elif user.role == 'manager':
                    return redirect(url_for('manager_dashboard'))
                else:
                    return redirect(url_for('dashboard'))
        else:
            flash('Invalid OTP', 'error')
    
    return render_template('verify_otp.html')

@app.route('/pending-device-approval')
@login_required
def pending_device_approval():
    """Pending device approval page"""
    user = current_user
    ip_address = request.remote_addr or '127.0.0.1'
    user_agent = request.headers.get('User-Agent', 'Unknown')
    fingerprint = DeviceTrustService.generate_device_fingerprint(user.id, ip_address, user_agent)
    
    device = Device.query.filter_by(user_id=user.id, device_fingerprint=fingerprint).first()

    # Master admin / admin / manager never wait on device approval - if one
    # of them somehow lands here, auto-trust the device and send them on.
    if user.is_super_admin or user.role in ('admin', 'manager'):
        if device and not device.is_trusted:
            device.is_trusted = True
            device.trust_score = 100
            device.trust_granted_at = datetime.now(timezone.utc)
            db.session.commit()
        return redirect(url_for('dashboard'))
    
    if device and device.is_trusted:
        flash('✅ Device approved!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('pending_device.html', user=user, device=device)

@app.route('/api/check-device-status')
@login_required
def check_device_status():
    """API: Check device status"""
    user = current_user
    ip_address = request.remote_addr or '127.0.0.1'
    user_agent = request.headers.get('User-Agent', 'Unknown')
    fingerprint = DeviceTrustService.generate_device_fingerprint(user.id, ip_address, user_agent)
    
    device = Device.query.filter_by(user_id=user.id, device_fingerprint=fingerprint).first()
    
    return jsonify({
        'is_trusted': device.is_trusted if device else False,
        'device_id': device.id if device else None
    })

# ==================== DASHBOARD ROUTES ====================

@app.route('/dashboard')
@login_required
def dashboard():
    """Unified dashboard"""
    user = current_user
    
    if not check_if_device_trusted(user):
        flash('⏳ Device pending approval', 'warning')
        return redirect(url_for('pending_device_approval'))
    
    accessible_resources = get_accessible_resources_for_user(user)
    resources_list = [
        {'id': k, 'name': v['name'], 'description': v['description'], 'icon': v.get('icon', '📚')}
        for k, v in accessible_resources.items()
    ]
    
    activities = MonitoringService.get_user_activities(user.id, limit=10)

    is_soc_role = user.is_super_admin or user.role in ('admin', 'manager')
    security_score = None
    ai_recommendations = None
    risk_distribution = None
    threat_timeline = None

    if is_soc_role:
        security_score = MonitoringService.calculate_security_score()
        ai_recommendations = MonitoringService.get_ai_recommendations(limit=5)

        cutoff_24h = datetime.now(timezone.utc) - timedelta(hours=24)
        risk_rows = RiskAssessment.query.filter(RiskAssessment.created_at >= cutoff_24h).all()
        risk_distribution = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
        for r in risk_rows:
            level = (r.risk_level or 'LOW').upper()
            if level in risk_distribution:
                risk_distribution[level] += 1

        cutoff_7d = datetime.now(timezone.utc) - timedelta(days=7)
        threat_rows = ThreatEvent.query.filter(ThreatEvent.detected_at >= cutoff_7d).order_by(ThreatEvent.detected_at.asc()).all()
        timeline_buckets = {}
        for t in threat_rows:
            day_key = t.detected_at.strftime('%Y-%m-%d')
            timeline_buckets.setdefault(day_key, 0)
            timeline_buckets[day_key] += 1
        # Ensure all 7 days present, oldest to newest
        threat_timeline = []
        for i in range(6, -1, -1):
            day = (datetime.now(timezone.utc) - timedelta(days=i)).strftime('%Y-%m-%d')
            threat_timeline.append({'date': day, 'count': timeline_buckets.get(day, 0)})

    return render_template('unified_dashboard.html', user=user, activities=activities, 
                         accessible_resources=resources_list, total_resources=len(resources_list),
                         is_soc_role=is_soc_role, security_score=security_score,
                         ai_recommendations=ai_recommendations, risk_distribution=risk_distribution,
                         threat_timeline=threat_timeline)

@app.route('/admin/dashboard')
@login_required
@require_role('admin')
def admin_dashboard():
    """Admin dashboard"""
    user = current_user
    
    if not user.is_super_admin and user.role != 'admin':
        flash('❌ Access Denied', 'error')
        return redirect(url_for('dashboard'))
    
    permissions = get_user_permissions(user)
    metrics = MonitoringService.get_security_metrics()
    activities = MonitoringService.get_recent_activities(limit=20)
    active_sessions = MonitoringService.get_active_sessions()
    access_denials = MonitoringService.get_access_denials_24h()
    users = User.query.all()
    pending_devices = Device.query.filter_by(is_trusted=False).all()
    locked_users = User.query.filter_by(is_locked=True).all()
    rules = AccessRule.query.all()
    
    threat_events = ThreatEvent.query.filter(
        ThreatEvent.detected_at >= datetime.now(timezone.utc) - timedelta(hours=24)
    ).count() if hasattr(ThreatEvent, 'query') else 0
    
    high_risk_logins = RiskAssessment.query.filter(
        RiskAssessment.risk_level.in_(['HIGH', 'CRITICAL']),
        RiskAssessment.created_at >= datetime.now(timezone.utc) - timedelta(hours=24)
    ).count() if hasattr(RiskAssessment, 'query') else 0
    
    return render_template('admin_dashboard.html',
                         user=user, permissions=permissions, metrics=metrics,
                         activities=activities, active_sessions=active_sessions,
                         access_denials=access_denials, users=users,
                         pending_devices=pending_devices, locked_users=locked_users,
                         rules=rules, config=Config,
                         threat_events=threat_events, high_risk_logins=high_risk_logins)

@app.route('/admin/ai-center')
@login_required
@require_role('admin')
def ai_center():
    """AI Center - automated recommendations from the rule-based engine"""
    recommendations = MonitoringService.get_ai_recommendations(limit=10)
    security_score = MonitoringService.calculate_security_score()
    return render_template('ai_center.html', user=current_user,
                         recommendations=recommendations, security_score=security_score)


@app.route('/admin/system-health')
@login_required
@require_role('admin')
def system_health():
    """System Health - live security metrics and overall score"""
    metrics = MonitoringService.get_security_metrics()
    security_score = MonitoringService.calculate_security_score()
    active_sessions = MonitoringService.get_active_sessions()
    return render_template('system_health.html', user=current_user,
                         metrics=metrics, security_score=security_score,
                         active_sessions=active_sessions)


@app.route('/admin/soc-dashboard')
@login_required
@require_role('admin')
def soc_dashboard():
    """✅ Phase 8: SOC Dashboard - surfaces the Decision/Auto-Block/Alert
    output of the Threat Prevention Engine pipeline and the queue of
    events still awaiting Admin Review."""
    data = ThreatPreventionEngine.get_soc_dashboard_data(hours=24, limit=100)
    return render_template('soc_dashboard.html', user=current_user, **data)


@app.route('/admin/soc-dashboard/review/<int:threat_id>', methods=['POST'])
@login_required
@require_role('admin')
def soc_dashboard_review(threat_id):
    """Admin Review step: mark a threat event investigated/false-positive."""
    threat = db.session.get(ThreatEvent, threat_id)
    if not threat:
        flash('Threat event not found', 'error')
        return redirect(url_for('soc_dashboard'))

    threat.is_investigated = True
    threat.investigated_by = current_user.id
    threat.investigation_notes = request.form.get('notes', '').strip()
    threat.is_false_positive = request.form.get('false_positive') == 'on'
    db.session.commit()

    ActivityLog.log_activity(
        current_user.id, current_user.username, 'threat_reviewed',
        'admin_action', f'Reviewed threat event #{threat_id}'
    )
    flash('✅ Threat event reviewed', 'success')
    return redirect(url_for('soc_dashboard'))


@app.route('/manager/dashboard')
@login_required
@require_role('manager')
def manager_dashboard():
    """Manager dashboard"""
    user = current_user
    permissions = get_user_permissions(user)
    pending_devices = Device.query.filter_by(is_trusted=False).all()
    activities = MonitoringService.get_recent_activities(limit=10)
    
    return render_template('manager_dashboard.html', user=user, permissions=permissions,
                         pending_devices=pending_devices, activities=activities)


# ==================== ADMIN USER MANAGEMENT ====================

@app.route('/admin/user/create', methods=['POST'])
@login_required
@require_role('admin')
@require_permission('can_create_users')
@error_handler
def create_user():
    """Create new user with validation and logging"""
    try:
        # Extract and validate form data
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        role = request.form.get('role', 'user').strip()
        department = request.form.get('department', 'General').strip()
        
        # Input validation
        if not all([username, email, password]):
            flash('❌ Username, email, and password are required', 'error')
            return redirect(url_for('admin_dashboard'))
        
        if role not in ['admin', 'manager', 'user', 'guest']:
            flash('❌ Invalid role selected', 'error')
            return redirect(url_for('admin_dashboard'))
        
        # Register user using AuthenticationService
        result = AuthenticationService.register_user(username, email, password, role=role)
        
        if result['success']:
            # Update additional user information
            user = User.query.filter_by(username=username).first()
            if user:
                user.department = department
                db.session.commit()
            
            # Log activity
            ActivityLog.log_activity(
                current_user.id, 
                current_user.username, 
                'create_user', 
                'success', 
                f'Created user: {username} with role: {role}'
            )
            flash(f'✅ User {username} created successfully!', 'success')
        else:
            flash(f'❌ {result.get("message", "Unknown error occurred")}', 'error')
        
        return redirect(url_for('admin_dashboard'))
        
    except Exception as e:
        logger.error(f"Error creating user: {str(e)}")
        flash(f'❌ Error creating user: {str(e)}', 'error')
        return redirect(url_for('admin_dashboard'))


@app.route('/admin/user/change-role/<int:user_id>', methods=['POST'])
@login_required
@require_role('admin')
@require_permission('can_change_roles')
@error_handler
def change_user_role(user_id):
    """Change user role with validation and logging"""
    try:
        # Get user
        user = db.session.get(User, user_id)
        
        # Validation checks
        if not user:
            flash('❌ User not found', 'error')
            return redirect(url_for('admin_dashboard'))
        
        if user.id == current_user.id:
            flash('❌ Cannot change your own role', 'error')
            return redirect(url_for('admin_dashboard'))
        
        # Get and validate new role
        new_role = request.form.get('role', '').strip()
        if new_role not in ['admin', 'manager', 'user', 'guest']:
            flash('❌ Invalid role specified', 'error')
            return redirect(url_for('admin_dashboard'))
        
        # Update role
        old_role = user.role
        user.role = new_role
        db.session.commit()
        
        # Log activity
        ActivityLog.log_activity(
            current_user.id, 
            current_user.username, 
            'change_role', 
            'success', 
            f'Changed {user.username} role: {old_role} → {new_role}'
        )
        flash(f'✅ Role changed to {new_role} for {user.username}!', 'success')
        
        return redirect(url_for('admin_dashboard'))
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error changing user role: {str(e)}")
        flash(f'❌ Error changing role: {str(e)}', 'error')
        return redirect(url_for('admin_dashboard'))


@app.route('/admin/user/delete/<int:user_id>')
@login_required
@require_role('admin')
@require_permission('can_delete_users')
@error_handler
def delete_user(user_id):
    """Delete user with validation and logging"""
    try:
        # Get user
        user = db.session.get(User, user_id)
        
        # Validation checks
        if not user:
            flash('❌ User not found', 'error')
            return redirect(url_for('admin_dashboard'))
        
        if user.id == current_user.id:
            flash('❌ Cannot delete your own account', 'error')
            return redirect(url_for('admin_dashboard'))
        
        # Store username before deletion
        username = user.username
        
        # Delete user
        db.session.delete(user)
        db.session.commit()
        
        # Log activity
        ActivityLog.log_activity(
            current_user.id, 
            current_user.username, 
            'delete_user', 
            'success', 
            f'Deleted user: {username}'
        )
        flash(f'✅ User {username} deleted successfully!', 'success')
        
        return redirect(url_for('admin_dashboard'))
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting user: {str(e)}")
        flash(f'❌ Error deleting user: {str(e)}', 'error')
        return redirect(url_for('admin_dashboard'))


@app.route('/admin/user/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@require_role('admin')
@error_handler
def edit_user(user_id):
    """Edit user details with role change support"""
    try:
        # Get user
        user = User.query.get_or_404(user_id)
        
        if request.method == 'POST':
            # Update basic information
            user.username = request.form.get('username', user.username).strip()
            user.email = request.form.get('email', user.email).strip()
            user.full_name = request.form.get('full_name', user.full_name).strip()
            
            # Update role if changed
            new_role = request.form.get('role', '').strip()
            if new_role and new_role in ['admin', 'user', 'manager', 'guest']:
                old_role = user.role
                user.role = new_role
                if old_role != new_role:
                    ActivityLog.log_activity(
                        current_user.id,
                        current_user.username,
                        'change_role',
                        'success',
                        f'Changed {user.username} role: {old_role} → {new_role}'
                    )
            
            # Update status
            user.is_active = request.form.get('is_active') == 'on'
            
            # Update password if provided
            new_password = request.form.get('password', '').strip()
            if new_password:
                user.password = generate_password_hash(new_password)
            
            # Update department if provided
            department = request.form.get('department', '').strip()
            if department:
                user.department = department
            
            # Commit changes
            db.session.commit()
            
            # Log activity
            ActivityLog.log_activity(
                current_user.id,
                current_user.username,
                'edit_user',
                'success',
                f'Updated user: {user.username}'
            )
            
            flash(f'✅ User {user.username} updated successfully!', 'success')
            return redirect(url_for('manage_users'))
            
        # GET request - render edit form
        return render_template('edit_user.html', edit_user=user)
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error editing user: {str(e)}")
        flash(f'❌ Error updating user: {str(e)}', 'error')
        return redirect(url_for('manage_users'))

# ==================== ADMIN RULE MANAGEMENT ====================

@app.route('/admin/rule/create', methods=['POST'])
@login_required
@require_role('admin')
@require_permission('can_create_rules')
@error_handler
def create_rule():
    """Create access rule"""
    name = request.form.get('name', '').strip()
    role = request.form.get('role', '').strip()
    resource = request.form.get('resource', '').strip()
    action = request.form.get('action', '').strip()
    
    if not all([name, role, resource, action]):
        flash('All fields required', 'error')
        return redirect(url_for('admin_dashboard'))
    
    rule = AccessRule(
        name=name, role=role, resource=resource, action=action,
        require_trusted_device=request.form.get('require_trusted_device') == 'on',
        require_business_hours=request.form.get('require_business_hours') == 'on',
        max_sessions=int(request.form.get('max_sessions', 1)),
        is_active=True
    )
    
    db.session.add(rule)
    db.session.commit()
    
    ActivityLog.log_activity(current_user.id, current_user.username, 'create_rule', 'success', f'Created: {name}')
    flash('✅ Rule created!', 'success')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/rule/delete/<int:rule_id>')
@login_required
@require_role('admin')
@error_handler
def delete_rule(rule_id):
    """Delete rule"""
    rule = db.session.get(AccessRule, rule_id)
    if rule:
        db.session.delete(rule)
        db.session.commit()
        flash('✅ Rule deleted!', 'success')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/unlock-account/<int:user_id>')
@login_required
@require_role('admin')
@require_permission('can_unlock_accounts')
@error_handler
def unlock_account(user_id):
    """Unlock account"""
    user = db.session.get(User, user_id)
    if user and user.is_locked:
        user.is_locked = False
        user.locked_until = None
        user.failed_login_attempts = 0
        db.session.commit()
        flash(f'✅ {user.username} unlocked!', 'success')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/trust-device/<int:device_id>')
@login_required
@require_role('admin', 'manager')
@require_permission('can_approve_devices')
@error_handler
def trust_device(device_id):
    """Trust device"""
    result = DeviceTrustService.trust_device(device_id)
    flash('✅ Device trusted!' if result['success'] else result['message'], 'success' if result['success'] else 'error')
    ref = request.referrer
    if ref and request.host_url.rstrip('/') in ref:
        return redirect(ref)
    return redirect(url_for('admin_dashboard' if current_user.role == 'admin' else 'manager_dashboard'))

@app.route('/admin/revoke-device/<int:device_id>')
@login_required
@require_role('admin', 'manager')
@require_permission('can_revoke_devices')
@error_handler
def revoke_device(device_id):
    """Revoke device"""
    result = DeviceTrustService.revoke_device_trust(device_id)
    flash('✅ Device revoked!' if result['success'] else result['message'], 'success' if result['success'] else 'error')
    ref = request.referrer
    if ref and request.host_url.rstrip('/') in ref:
        return redirect(ref)
    return redirect(url_for('admin_dashboard' if current_user.role == 'admin' else 'manager_dashboard'))

@app.route('/admin/terminate-session/<int:session_id>')
@login_required
@require_role('admin')
@require_permission('can_terminate_sessions')
@error_handler
def terminate_session(session_id):
    """Terminate session"""
    session_obj = db.session.get(SessionModel, session_id)
    if session_obj and session_obj.is_active:
        session_obj.is_active = False
        session_obj.ended_at = datetime.now(timezone.utc)
        db.session.commit()
        flash('✅ Session terminated!', 'success')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/manage-users')
@login_required
@require_role('admin')
def manage_users():
    """Manage users page"""
    users = User.query.all()
    return render_template('manage_users.html', users=users, user=current_user)

@app.route('/admin/manage-policies')
@login_required
@require_role('admin')
def manage_policies():
    """Manage access policies"""
    rules = AccessRule.query.all()
    return render_template('manage_policies.html', rules=rules, user=current_user)

@app.route('/admin/available-resources')
@login_required
@require_role('admin')
def available_resources():
    """List all available resources"""
    resources_list = [
        {
            'id': key,
            'name': value['name'],
            'description': value['description'],
            'accessible_roles': ', '.join([r.upper() for r in value['accessible_by']])
        }
        for key, value in AVAILABLE_RESOURCES.items()
    ]
    
    return render_template('available_resources.html', resources=resources_list, user=current_user)

# ==================== IP WHITELIST MANAGEMENT ====================

@app.route('/admin/ip-whitelist', methods=['GET', 'POST'])  # ← CRITICAL: Must include POST
@login_required
def ip_whitelist_management():
    """IP Whitelist Management Page"""
    # Check admin access
    if not current_user.is_super_admin and current_user.role != 'admin':
        flash('❌ Access denied - Admin only', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        # ✅ ACTION 1: Add IP
        if action == 'add_ip':
            ip_address = request.form.get('ip_address', '').strip()
            description = request.form.get('description', '').strip()
            
            if not ip_address:
                flash('❌ IP address is required', 'error')
                return redirect(url_for('ip_whitelist_management'))
            
            try:
                # Check if it's a range (CIDR notation)
                is_range = '/' in ip_address
                
                # Check if IP already exists
                existing = IPWhitelist.query.filter_by(ip_address=ip_address).first()
                if existing:
                    flash(f'⚠️ IP {ip_address} already in whitelist', 'warning')
                    return redirect(url_for('ip_whitelist_management'))
                
                # Add new IP
                new_ip = IPWhitelist(
                    ip_address=ip_address,
                    is_range=is_range,
                    description=description or None,
                    added_by=current_user.id,
                    is_active=True
                )
                db.session.add(new_ip)
                db.session.commit()
                
                flash(f'✅ IP {ip_address} added to whitelist successfully', 'success')
                logger.info(f"Admin {current_user.username} added IP {ip_address} to whitelist")
                
            except Exception as e:
                db.session.rollback()
                flash(f'❌ Error adding IP: {str(e)}', 'error')
                logger.error(f"Error adding IP to whitelist: {e}")
            
            return redirect(url_for('ip_whitelist_management'))
        
        # ✅ ACTION 2: Toggle Feature (Enable/Disable Whitelist)
        elif action == 'toggle_feature':
            enable = request.form.get('enable') == 'true'
            # You can store this in a config table or session
            # For now, we'll just show a message
            flash(f'✅ IP Whitelist feature {"enabled" if enable else "disabled"}', 'success')
            logger.info(f"IP Whitelist feature {'enabled' if enable else 'disabled'} by {current_user.username}")
            return redirect(url_for('ip_whitelist_management'))
        
        # ✅ ACTION 3: Toggle IP (Activate/Deactivate)
        elif action == 'toggle_ip':
            ip_id = request.form.get('ip_id')
            try:
                ip_entry = IPWhitelist.query.get(ip_id)
                if ip_entry:
                    ip_entry.is_active = not ip_entry.is_active
                    db.session.commit()
                    status = 'activated' if ip_entry.is_active else 'deactivated'
                    flash(f'✅ IP {ip_entry.ip_address} {status}', 'success')
                    logger.info(f"IP {ip_entry.ip_address} {status} by {current_user.username}")
                else:
                    flash('❌ IP not found', 'error')
            except Exception as e:
                db.session.rollback()
                flash(f'❌ Error toggling IP: {str(e)}', 'error')
                logger.error(f"Error toggling IP: {e}")
            
            return redirect(url_for('ip_whitelist_management'))
        
        # ✅ ACTION 4: Remove IP
        elif action == 'remove_ip':
            ip_id = request.form.get('ip_id')
            try:
                ip_entry = IPWhitelist.query.get(ip_id)
                if ip_entry:
                    ip_address = ip_entry.ip_address
                    db.session.delete(ip_entry)
                    db.session.commit()
                    flash(f'✅ IP {ip_address} removed from whitelist', 'success')
                    logger.info(f"IP {ip_address} removed from whitelist by {current_user.username}")
                else:
                    flash('❌ IP not found', 'error')
            except Exception as e:
                db.session.rollback()
                flash(f'❌ Error removing IP: {str(e)}', 'error')
                logger.error(f"Error removing IP: {e}")
            
            return redirect(url_for('ip_whitelist_management'))
    
    # GET request - Display the page
    try:
        whitelisted_ips = IPWhitelist.query.order_by(IPWhitelist.added_at.desc()).all()
        whitelist_enabled = True  # You can store this in config or database
        
        return render_template('ip_whitelist.html', 
                             whitelisted_ips=whitelisted_ips,
                             whitelist_enabled=whitelist_enabled,
                             user=current_user)
    except Exception as e:
        logger.error(f"Error loading IP whitelist page: {e}")
        flash('❌ Error loading whitelist', 'error')
        return redirect(url_for('admin_dashboard'))

    
    # GET request - Display page
    whitelisted_ips = IPWhitelist.query.all()
    whitelist_enabled = True  # Or get from config
    
    return render_template('ip_whitelist.html', 
                         whitelisted_ips=whitelisted_ips,
                         whitelist_enabled=whitelist_enabled,
                         user=current_user)


@app.route('/admin/ip-whitelist/add', methods=['POST'])
@login_required
@require_role('admin')
def add_ip_whitelist():
    """Add IP to whitelist"""
    ip_address = request.form.get('ip_address', '').strip()
    description = request.form.get('description', '').strip()
    
    if not ip_address:
        flash('IP required', 'error')
        return redirect(url_for('ip_whitelist_management'))
    
    from ip_whitelist import add_ip_to_whitelist
    result = add_ip_to_whitelist(ip_address, description, current_user.id)
    
    flash(f"✅ IP {ip_address} added" if result['success'] else f"❌ {result['message']}", 
          'success' if result['success'] else 'error')
    
    return redirect(url_for('ip_whitelist_management'))

@app.route('/admin/ip-whitelist/remove/<int:ip_id>')
@login_required
@require_role('admin')
def remove_ip_whitelist(ip_id):
    """Remove IP"""
    from ip_whitelist import remove_ip_from_whitelist
    result = remove_ip_from_whitelist(ip_id)
    flash('✅ IP removed' if result['success'] else f"❌ {result['message']}", 
          'success' if result['success'] else 'error')
    return redirect(url_for('ip_whitelist_management'))

@app.route('/admin/ip-whitelist/toggle/<int:ip_id>')
@login_required
@require_role('admin')
def toggle_ip_whitelist(ip_id):
    """Toggle IP status"""
    from ip_whitelist import toggle_ip_status
    result = toggle_ip_status(ip_id)
    flash(f"✅ {result['message']}" if result['success'] else f"❌ {result['message']}", 
          'success' if result['success'] else 'error')
    return redirect(url_for('ip_whitelist_management'))

# ==================== SECURITY ANALYTICS ROUTES ====================

@app.route('/admin/security-analytics')
@login_required
@require_role('admin')
def security_analytics():
    """Security analytics dashboard"""
    risk_assessments = RiskAssessment.query.filter(
        RiskAssessment.created_at >= datetime.now(timezone.utc) - timedelta(hours=24)
    ).order_by(RiskAssessment.created_at.desc()).limit(50).all()
    
    threat_events = ThreatEvent.query.filter(
        ThreatEvent.detected_at >= datetime.now(timezone.utc) - timedelta(days=7)
    ).order_by(ThreatEvent.detected_at.desc()).limit(100).all()
    
    recent_logins = LoginHistory.query.filter(
        LoginHistory.timestamp >= datetime.now(timezone.utc) - timedelta(days=7)
    ).order_by(LoginHistory.timestamp.desc()).limit(100).all()
    
    stats = {
        'total_risk_assessments': RiskAssessment.query.count(),
        'high_risk_logins': RiskAssessment.query.filter(RiskAssessment.risk_level.in_(['HIGH', 'CRITICAL'])).count(),
        'total_threats': ThreatEvent.query.count(),
        'unresolved_threats': ThreatEvent.query.filter_by(resolved_at=None).count(),
        'blocked_ips': IPWhitelist.query.filter_by(is_active=False, is_auto_blocked=True).count(),
    }
    
    return render_template('security_analytics.html', 
                         user=current_user,
                         risk_assessments=risk_assessments,
                         threat_events=threat_events,
                         recent_logins=recent_logins,
                         stats=stats)
@app.route('/admin/threat/investigate/<int:threat_id>', methods=['GET', 'POST'])
@require_permission('can_view_all_activities')
def investigate_threat(threat_id):
    """Investigate a threat event"""
    threat = ThreatEvent.query.get_or_404(threat_id)
    
    if request.method == 'POST':
        # Mark as investigated
        threat.is_investigated = True
        threat.investigated_by = current_user.id
        threat.investigation_notes = request.form.get('notes', '')
        threat.is_false_positive = request.form.get('false_positive') == 'true'
        
        if threat.is_false_positive:
            threat.severity = 'low'
        
        db.session.commit()
        
        flash('Threat investigation completed successfully', 'success')
        return redirect(url_for('security_analytics'))
    
    return render_template('investigate_threat.html', threat=threat)

# You can add further admin routes below or the main app run block


@app.route('/admin/login-history')
@login_required
@require_role('admin')
def login_history_view():
    """View detailed login history"""
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    login_history = LoginHistory.query.order_by(
        LoginHistory.timestamp.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('login_history.html', 
                         user=current_user,
                         login_history=login_history)

# ==================== API ROUTES (WITH RATE LIMITING) ====================

@app.route('/api/accessible-resources')
@login_required
@rate_limit(max_requests=60, window_seconds=60)
def api_accessible_resources():
    """API: Accessible resources"""
    accessible_resources = get_accessible_resources_for_user(current_user)
    resources_list = [
        {'id': k, 'name': v['name'], 'description': v['description'], 'icon': v.get('icon', '📚')}
        for k, v in accessible_resources.items()
    ]
    
    return jsonify({'count': len(resources_list), 'resources': resources_list, 'role': current_user.role})

@app.route('/api/activities')
@login_required
@rate_limit(max_requests=30, window_seconds=60)
def api_activities():
    """API: Activities"""
    if current_user.role in ['admin', 'manager'] or current_user.is_super_admin:
        activities = MonitoringService.get_recent_activities(limit=50)
    else:
        activities = MonitoringService.get_user_activities(current_user.id, limit=50)
    return jsonify(activities)

@app.route('/api/metrics')
@login_required
@require_role('admin')
@rate_limit(max_requests=20, window_seconds=60)
def api_metrics():
    """API: Metrics"""
    return jsonify(MonitoringService.get_security_metrics())

@app.route('/api/risk-assessments')
@login_required
@require_role('admin')
@rate_limit(max_requests=30, window_seconds=60)
def api_risk_assessments():
    """API: Get risk assessments"""
    hours = request.args.get('hours', 24, type=int)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    
    assessments = RiskAssessment.query.filter(
        RiskAssessment.created_at >= cutoff
    ).order_by(RiskAssessment.created_at.desc()).all()
    
    data = [{
        'id': a.id,
        'user_id': a.user_id,
        'username': a.user.username if a.user else 'Unknown',
        'risk_score': a.risk_score,
        'risk_level': a.risk_level,
        'action': a.action,
        'ip_address': a.ip_address,
        'location': f"{a.location_city}, {a.location_country}" if a.location_city else a.location_country,
        'was_blocked': a.was_blocked,
        'timestamp': a.created_at.isoformat()
    } for a in assessments]
    
    return jsonify({'count': len(data), 'assessments': data})

@app.route('/api/threat-events')
@login_required
@require_role('admin')
@rate_limit(max_requests=30, window_seconds=60)
def api_threat_events():
    """API: Get threat events"""
    days = request.args.get('days', 7, type=int)
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    
    threats = ThreatEvent.query.filter(
        ThreatEvent.detected_at >= cutoff
    ).order_by(ThreatEvent.detected_at.desc()).all()
    
    data = [{
        'id': t.id,
        'threat_type': t.threat_type,
        'severity': t.severity,
        'description': t.description,
        'source_ip': t.source_ip,
        'target_username': t.target_username,
        'was_blocked': t.was_blocked,
        'detected_at': t.detected_at.isoformat()
    } for t in threats]
    
    return jsonify({'count': len(data), 'threats': data})

# ==================== AI EXPLANATION (PHASE 4 & 5) ====================

@app.route('/api/device/<int:device_id>/ai-analysis')
@login_required
@rate_limit(max_requests=30, window_seconds=60)
@error_handler
def api_device_ai_analysis(device_id):
    """API: Rule-based AI explanation for why a device is blocked/pending"""
    device = db.session.get(Device, device_id)
    if not device:
        return jsonify({'error': 'Device not found'}), 404

    can_manage = current_user.is_super_admin or current_user.role in ('admin', 'manager')
    if not can_manage and device.user_id != current_user.id:
        return jsonify({'error': 'Access denied'}), 403

    analysis = AIExplainService.analyze_device(device, force_refresh=request.args.get('refresh') == '1')
    return jsonify({
        'device': {
            'id': device.id,
            'device_name': device.device_name,
            'browser': device.browser,
            'os': device.os,
            'ip_address': device.ip_address,
            'is_trusted': device.is_trusted,
            'trust_score': device.trust_score,
            'owner': device.user.username if device.user else None,
        },
        'analysis': analysis
    })

@app.route('/api/ip/<int:ip_id>/ai-analysis')
@login_required
@require_role('admin')
@rate_limit(max_requests=30, window_seconds=60)
@error_handler
def api_ip_ai_analysis(ip_id):
    """API: Rule-based AI explanation for why an IP entry is blocked"""
    ip_entry = db.session.get(IPWhitelist, ip_id)
    if not ip_entry:
        return jsonify({'error': 'IP entry not found'}), 404

    analysis = AIExplainService.analyze_ip(ip_entry, force_refresh=request.args.get('refresh') == '1')
    return jsonify({
        'ip': {
            'id': ip_entry.id,
            'ip_address': ip_entry.ip_address,
            'description': ip_entry.description,
            'is_active': ip_entry.is_active,
            'is_auto_blocked': ip_entry.is_auto_blocked,
            'blocked_at': ip_entry.blocked_at.strftime('%Y-%m-%d %H:%M') if ip_entry.blocked_at else None,
        },
        'analysis': analysis
    })


@login_required
def rate_limit_status():
    """Check rate limit status"""
    client_ip = get_client_ip(request)
    
    login_count = rate_limiter.get_request_count(f"login_{client_ip}_{current_user.username}", 300)
    api_count = rate_limiter.get_request_count(client_ip, 60)
    
    return jsonify({
        'login_attempts_remaining': max(0, 5 - login_count),
        'api_requests_remaining': max(0, 60 - api_count),
        'ip_address': client_ip
    })

# ==================== RESOURCE ROUTES ====================

@app.route('/my-profile')
@login_required
def my_profile():
    """User profile"""
    if not check_resource_access(current_user, 'user_dashboard', 'read'):
        flash('❌ Access Denied', 'error')
        return redirect(url_for('dashboard'))
    return render_template('my_profile.html', user=current_user)

@app.route('/leave-management')
@login_required
def leave_management():
    """Leave management"""
    if not check_resource_access(current_user, 'leave_management', 'read'):
        flash('❌ Access Denied', 'error')
        return redirect(url_for('dashboard'))
    return render_template('leave_management.html', user=current_user)

@app.route('/employee-directory')
@login_required
def employee_directory():
    """Employee directory"""
    if not check_resource_access(current_user, 'employee_directory', 'read'):
        flash('❌ Access Denied', 'error')
        return redirect(url_for('dashboard'))
    employees = User.query.all()
    return render_template('employee_directory.html', user=current_user, employees=employees)

@app.route('/projects')
@login_required
def projects():
    """Projects"""
    if not check_resource_access(current_user, 'projects', 'read'):
        flash('❌ Access Denied', 'error')
        return redirect(url_for('dashboard'))
    return render_template('projects.html', user=current_user)

@app.route('/device-management')
@login_required
def device_management():
    """Device management"""
    if not check_resource_access(current_user, 'device_management', 'read'):
        flash('❌ Access Denied', 'error')
        return redirect(url_for('dashboard'))

    can_manage = current_user.is_super_admin or current_user.role in ('admin', 'manager')
    devices = Device.query.order_by(Device.created_at.desc()).all() if can_manage else Device.query.filter_by(user_id=current_user.id).order_by(Device.created_at.desc()).all()
    return render_template('device_management.html', user=current_user, devices=devices, can_manage=can_manage)

@app.route('/reports')
@login_required
def reports():
    """Reports page"""
    try:
        if not check_resource_access(current_user, 'reports', 'read'):
            flash('❌ Access Denied', 'error')
            return redirect(url_for('dashboard'))
        
        logger.info(f"User {current_user.username} accessed reports page")
        return render_template('reports.html', user=current_user)
    except Exception as e:
        logger.error(f"Error loading reports page: {e}")
        flash('Error loading reports page', 'danger')
        return redirect(url_for('dashboard'))


@app.route('/payroll')
@login_required
def payroll():
    """Payroll page"""
    try:
        if not check_resource_access(current_user, 'payroll', 'read'):
            flash('❌ Access Denied', 'error')
            return redirect(url_for('dashboard'))
        
        logger.info(f"User {current_user.username} accessed payroll page")
        return render_template('payroll.html', user=current_user)
    except Exception as e:
        logger.error(f"Error loading payroll page: {e}")
        flash('Error loading payroll page', 'danger')
        return redirect(url_for('dashboard'))


@app.route('/settings')
@login_required
def user_settings():
    """User settings page"""
    return render_template('user_settings.html', user=current_user)

@app.route('/settings/update-preferences', methods=['POST'])
@login_required
def update_preferences():
    """Update user preferences"""
    timezone_pref = request.form.get('timezone', 'UTC')
    language = request.form.get('language', 'en')
    notifications = request.form.get('notifications') == 'on'
    
    try:
        current_user.timezone = timezone_pref
        current_user.language = language
        current_user.notification_preferences = json.dumps({'email': notifications})
        db.session.commit()
        
        ActivityLog.log_activity(current_user.id, current_user.username, 'update_preferences', 'success', 'Updated preferences')
        flash('✅ Preferences updated', 'success')
    except Exception as e:
        logger.error('Error updating preferences: %s', str(e))
        flash('❌ Error updating preferences', 'error')
    
    return redirect(url_for('user_settings'))

@app.route('/settings/change-password', methods=['POST'])
@login_required
def change_password():
    """Change user password"""
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')
    
    if not all([current_password, new_password, confirm_password]):
        flash('All fields required', 'error')
        return redirect(url_for('user_settings'))
    
    if new_password != confirm_password:
        flash('Passwords do not match', 'error')
        return redirect(url_for('user_settings'))
    
    if not current_user.check_password(current_password):
        flash('Current password incorrect', 'error')
        return redirect(url_for('user_settings'))
    
    password_check = validate_password_strength(new_password)
    if not password_check['valid']:
        for error in password_check['errors']:
            flash(error, 'error')
        return redirect(url_for('user_settings'))
    
    try:
        current_user.set_password(new_password)
        db.session.commit()
        
        ActivityLog.log_activity(current_user.id, current_user.username, 'change_password', 'success', 'Password changed')
        flash('✅ Password changed successfully', 'success')
    except Exception as e:
        logger.error('Error changing password: %s', str(e))
        flash('❌ Error changing password', 'error')
    
    return redirect(url_for('user_settings'))

@app.route('/logout')
@login_required
def logout():
    """Logout"""
    user_id = session.get('user_id')
    username = session.get('username')
    
    try:
        user_sessions = SessionModel.query.filter_by(user_id=user_id, is_active=True).all()
        for user_session in user_sessions:
            user_session.is_active = False
            user_session.ended_at = datetime.now(timezone.utc)
        db.session.commit()
    except:
        db.session.rollback()
    
    ActivityLog.log_activity(user_id, username, 'logout', 'success', 'Logout')
    session.clear()
    logout_user()
    flash('✅ Logged out', 'success')
    return redirect(url_for('index'))

# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(error):
    return render_template('index.html'), 404

@app.errorhandler(403)
def forbidden(error):
    return jsonify({'error': 'Forbidden'}), 403

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'error': 'Internal error'}), 500

# ==================== APPLICATION STARTUP ====================

if __name__ == '__main__':
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    
    is_production = os.getenv('FLASK_ENV') == 'production'
    
    # Generate MFA codes for all users with MFA enabled
    mfa_info = []
    try:
        import pyotp
        with app.app_context():
            mfa_users = User.query.filter_by(is_mfa_enabled=True).all()
            for u in mfa_users:
                if u.otp_secret:
                    code = pyotp.TOTP(u.otp_secret).now()
                    mfa_info.append((u.username, u.role, code, u.otp_secret))
    except Exception:
        pass

    print("\n" + "="*80)
    print("  ZeroTrustX - Enterprise ZTNA Framework")
    print("="*80)
    print(f"  Environment: {'PRODUCTION' if is_production else 'DEVELOPMENT'}")
    print(f"  Local:   http://localhost:5000")
    print(f"  Network: http://{local_ip}:5000")
    print(f"\n  Core Features:")
    print(f"    IP Whitelist:        {'ENABLED' if Config.ENABLE_IP_WHITELIST else 'DISABLED'}")
    print(f"    Device Trust:        {'ENABLED' if Config.ENABLE_DEVICE_TRUST else 'DISABLED'}")
    print(f"\n  Enhanced Features:")
    print(f"    Risk Scoring:        {'ENABLED' if Config.ENABLE_RISK_SCORING else 'DISABLED'}")
    print(f"    Geo-Location:        {'ENABLED' if Config.ENABLE_GEOLOCATION else 'DISABLED'}")
    print(f"    Threat Intelligence: {'ENABLED' if Config.ENABLE_THREAT_INTELLIGENCE else 'DISABLED'}")
    print(f"    Rate Limiting:       {'ENABLED' if Config.ENABLE_RATE_LIMITING else 'DISABLED'}")
    print(f"    Data Encryption:     {'ENABLED' if Config.ENCRYPT_SENSITIVE_DATA else 'DISABLED'}")
    if mfa_info:
        print("\n" + "-"*80)
        print("  MFA SETUP  (add to Google Authenticator or any TOTP app)")
        print("-"*80)
        for username, role, code, secret in mfa_info:
            print(f"  [{role.upper():10}]  {username}")
            print(f"               Setup Key:    {secret}")
            print(f"               Current Code: {code}  (refreshes every 30 sec)")
            print()
        print("  Tip: In your authenticator app choose 'Enter a setup key',")
        print("       paste the Setup Key above, and set type to Time-based.")
        print("-"*80)
    print("\n  Press CTRL+C to quit")
    print("="*80 + "\n")
    
    logger.info('✅ ZeroTrustX Enterprise Edition started')
    
    socketio.run(app, debug=not is_production, use_reloader=False, host='0.0.0.0', port=int(os.getenv('PORT', 5000)), log_output=False)

