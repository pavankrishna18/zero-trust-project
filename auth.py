"""
Authentication Service for ZeroTrustX
Handles user authentication, MFA, session management, and JWT tokens
"""

import jwt
import uuid
import logging
from datetime import datetime, timezone, timedelta
from flask import request
from models import db, User, Session
import pyotp

logger = logging.getLogger(__name__)

class AuthenticationService:
    """Service for handling user authentication and authorization"""
    
    # JWT Configuration
    JWT_SECRET = 'your-super-secret-key-change-in-production'
    JWT_ALGORITHM = 'HS256'
    JWT_EXPIRATION_HOURS = 24
    
    # Session Configuration
    SESSION_EXPIRATION_HOURS = 24
    MAX_FAILED_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 30
    
    @staticmethod
    def register_user(username, email, password, role='user'):
        """
        Register a new user
        
        Args:
            username: User's username
            email: User's email
            password: User's password
            role: User's role (admin, manager, user, guest)
        
        Returns:
            Dictionary with success status and user data
        """
        try:
            # Check if user already exists
            if User.query.filter_by(username=username).first():
                return {
                    'success': False,
                    'message': f'Username "{username}" already exists'
                }
            
            if User.query.filter_by(email=email).first():
                return {
                    'success': False,
                    'message': f'Email "{email}" already registered'
                }
            
            # Create new user
            user = User(
                username=username,
                email=email,
                role=role,
                is_active=True
            )
            
            # Set password (hashed)
            user.set_password(password)
            
            # Generate OTP secret for 2FA
            otp_secret = user.generate_otp_secret()
            
            # Add user to database
            db.session.add(user)
            db.session.commit()
            
            logger.info('User %s registered successfully with role %s', username, role)
            
            return {
                'success': True,
                'user': user,
                'otp_secret': otp_secret,
                'message': f'User {username} registered successfully'
            }
        
        except Exception as e:
            logger.error('Error registering user: %s', str(e))
            db.session.rollback()
            return {
                'success': False,
                'message': f'Error registering user: {str(e)}'
            }
    
    @staticmethod
    def authenticate_user(username, password):
        """
        Authenticate user with username and password
        
        Args:
            username: User's username
            password: User's password
        
        Returns:
            Dictionary with success status and user data
        """
        try:
            user = User.query.filter_by(username=username).first()
            
            if not user:
                logger.warning('Login attempt for non-existent user: %s', username)
                return {
                    'success': False,
                    'message': 'Invalid username or password'
                }
            
            # Check if account is locked
            if user.is_account_locked():
                logger.warning('Login attempt on locked account: %s', username)
                return {
                    'success': False,
                    'message': f'Account is locked. Try again later.'
                }
            
            # Check if account is active
            if not user.is_active:
                logger.warning('Login attempt on inactive account: %s', username)
                return {
                    'success': False,
                    'message': 'Account is inactive'
                }
            
            # Verify password
            if not user.check_password(password):
                user.increment_failed_login_attempts()
                logger.warning('Failed login attempt for user %s (attempt %d)', username, user.failed_login_attempts)
                return {
                    'success': False,
                    'message': f'Invalid username or password'
                }
            
            # Reset failed login attempts on successful authentication
            user.reset_failed_login_attempts()
            
            logger.info('User %s authenticated successfully', username)
            
            return {
                'success': True,
                'user': user,
                'message': 'Authentication successful'
            }
        
        except Exception as e:
            logger.error('Error during authentication: %s', str(e))
            return {
                'success': False,
                'message': f'Error during authentication: {str(e)}'
            }
    
    @staticmethod
    def verify_otp(otp_secret, otp_token):
        """
        Verify OTP token
        
        Args:
            otp_secret: User's OTP secret
            otp_token: OTP token to verify
        
        Returns:
            Boolean indicating if OTP is valid
        """
        try:
            if not otp_secret:
                logger.warning('OTP verification attempted without secret')
                return False
            
            totp = pyotp.TOTP(otp_secret)
            is_valid = totp.verify(otp_token, valid_window=1)
            
            if is_valid:
                logger.info('OTP verified successfully')
            else:
                logger.warning('OTP verification failed: Invalid token')
            
            return is_valid
        
        except Exception as e:
            logger.error('Error verifying OTP: %s', str(e))
            return False
    
    @staticmethod
    def get_otp_uri(username, otp_secret):
        """
        Get OTP provisioning URI for QR code generation
        
        Args:
            username: User's username/email
            otp_secret: User's OTP secret
        
        Returns:
            OTP URI string
        """
        try:
            totp = pyotp.TOTP(otp_secret)
            uri = totp.provisioning_uri(name=username, issuer_name='ZeroTrustX')
            return uri
        except Exception as e:
            logger.error('Error generating OTP URI: %s', str(e))
            return None
    
    @staticmethod
    def create_session(user, device_fingerprint, user_agent=None):
        """
        Create a new session for user
        
        Args:
            user: User object
            device_fingerprint: Device fingerprint
            user_agent: User agent string (optional)
        
        Returns:
            Dictionary with success status and session data
        """
        try:
            # ✅ DEFAULT user_agent if not provided
            if not user_agent:
                user_agent = 'Unknown Browser'
            
            # Generate session token
            session_token = str(uuid.uuid4())
            
            # Get IP address
            ip_address = request.remote_addr or '127.0.0.1'
            
            # Calculate expiration
            expires_at = datetime.now(timezone.utc) + timedelta(hours=AuthenticationService.SESSION_EXPIRATION_HOURS)
            
            # Create session
            new_session = Session(
                user_id=user.id,
                session_token=session_token,
                device_fingerprint=device_fingerprint,
                ip_address=ip_address,
                user_agent=user_agent,  # ✅ USE user_agent
                is_active=True,
                created_at=datetime.now(timezone.utc),
                expires_at=expires_at
            )
            
            db.session.add(new_session)
            db.session.commit()
            
            # Generate JWT token
            jwt_token = AuthenticationService.generate_jwt_token(user.id, session_token)
            
            logger.info('Session created for user %s', user.username)
            
            return {
                'success': True,
                'session': new_session,
                'jwt_token': jwt_token,
                'message': 'Session created successfully'
            }
        
        except Exception as e:
            logger.error('Error creating session: %s', str(e))
            db.session.rollback()
            return {
                'success': False,
                'message': f'Error creating session: {str(e)}'
            }
    
    @staticmethod
    def generate_jwt_token(user_id, session_token):
        """
        Generate JWT token for user session
        
        Args:
            user_id: User ID
            session_token: Session token
        
        Returns:
            JWT token string
        """
        try:
            payload = {
                'user_id': user_id,
                'session_token': session_token,
                'iat': datetime.now(timezone.utc),
                'exp': datetime.now(timezone.utc) + timedelta(hours=AuthenticationService.JWT_EXPIRATION_HOURS)
            }
            
            token = jwt.encode(
                payload,
                AuthenticationService.JWT_SECRET,
                algorithm=AuthenticationService.JWT_ALGORITHM
            )
            
            logger.info('JWT token generated for user %s', user_id)
            
            return token
        
        except Exception as e:
            logger.error('Error generating JWT token: %s', str(e))
            return None
    
    @staticmethod
    def verify_jwt_token(token):
        """
        Verify JWT token
        
        Args:
            token: JWT token to verify
        
        Returns:
            Dictionary with payload if valid, None if invalid
        """
        try:
            payload = jwt.decode(
                token,
                AuthenticationService.JWT_SECRET,
                algorithms=[AuthenticationService.JWT_ALGORITHM]
            )
            
            logger.info('JWT token verified for user %s', payload.get('user_id'))
            
            return payload
        
        except jwt.ExpiredSignatureError:
            logger.warning('JWT token expired')
            return None
        
        except jwt.InvalidTokenError as e:
            logger.warning('Invalid JWT token: %s', str(e))
            return None
        
        except Exception as e:
            logger.error('Error verifying JWT token: %s', str(e))
            return None
    
    @staticmethod
    def validate_session(session_token):
        """
        Validate session token
        
        Args:
            session_token: Session token to validate
        
        Returns:
            Session object if valid, None if invalid
        """
        try:
            session = Session.query.filter_by(session_token=session_token).first()
            
            if not session:
                logger.warning('Session not found: %s', session_token)
                return None
            
            # Check if session is active
            if not session.is_active:
                logger.warning('Session is not active: %s', session_token)
                return None
            
            # Check if session is expired
            if session.is_expired():
                session.is_active = False
                session.ended_at = datetime.now(timezone.utc)
                db.session.commit()
                logger.warning('Session expired: %s', session_token)
                return None
            
            logger.info('Session validated: %s', session_token)
            
            return session
        
        except Exception as e:
            logger.error('Error validating session: %s', str(e))
            return None
    
    @staticmethod
    def revoke_session(session_token):
        """
        Revoke a session (logout)
        
        Args:
            session_token: Session token to revoke
        
        Returns:
            Boolean indicating success
        """
        try:
            session = Session.query.filter_by(session_token=session_token).first()
            
            if not session:
                logger.warning('Session not found for revocation: %s', session_token)
                return False
            
            session.is_active = False
            session.ended_at = datetime.now(timezone.utc)
            db.session.commit()
            
            logger.info('Session revoked: %s', session_token)
            
            return True
        
        except Exception as e:
            logger.error('Error revoking session: %s', str(e))
            db.session.rollback()
            return False
    
    @staticmethod
    def revoke_all_user_sessions(user_id):
        """
        Revoke all sessions for a user (force logout)
        
        Args:
            user_id: User ID
        
        Returns:
            Number of sessions revoked
        """
        try:
            sessions = Session.query.filter_by(user_id=user_id, is_active=True).all()
            
            for session in sessions:
                session.is_active = False
                session.ended_at = datetime.now(timezone.utc)
            
            db.session.commit()
            
            logger.info('Revoked %d sessions for user %s', len(sessions), user_id)
            
            return len(sessions)
        
        except Exception as e:
            logger.error('Error revoking user sessions: %s', str(e))
            db.session.rollback()
            return 0
    
    @staticmethod
    def change_password(user, old_password, new_password):
        """
        Change user password
        
        Args:
            user: User object
            old_password: Old password
            new_password: New password
        
        Returns:
            Dictionary with success status
        """
        try:
            # Verify old password
            if not user.check_password(old_password):
                logger.warning('Password change failed: Invalid old password for %s', user.username)
                return {
                    'success': False,
                    'message': 'Invalid old password'
                }
            
            # Set new password
            user.set_password(new_password)
            db.session.commit()
            
            logger.info('Password changed for user %s', user.username)
            
            return {
                'success': True,
                'message': 'Password changed successfully'
            }
        
        except Exception as e:
            logger.error('Error changing password: %s', str(e))
            db.session.rollback()
            return {
                'success': False,
                'message': f'Error changing password: {str(e)}'
            }
    
    @staticmethod
    def enable_2fa(user):
        """
        Enable 2FA for user
        
        Args:
            user: User object
        
        Returns:
            Dictionary with OTP secret
        """
        try:
            otp_secret = user.generate_otp_secret()
            user.is_mfa_enabled = True
            db.session.commit()
            
            logger.info('2FA enabled for user %s', user.username)
            
            return {
                'success': True,
                'otp_secret': otp_secret,
                'message': '2FA enabled successfully'
            }
        
        except Exception as e:
            logger.error('Error enabling 2FA: %s', str(e))
            db.session.rollback()
            return {
                'success': False,
                'message': f'Error enabling 2FA: {str(e)}'
            }
    
    @staticmethod
    def disable_2fa(user):
        """
        Disable 2FA for user
        
        Args:
            user: User object
        
        Returns:
            Dictionary with success status
        """
        try:
            user.is_mfa_enabled = False
            user.otp_secret = None
            db.session.commit()
            
            logger.info('2FA disabled for user %s', user.username)
            
            return {
                'success': True,
                'message': '2FA disabled successfully'
            }
        
        except Exception as e:
            logger.error('Error disabling 2FA: %s', str(e))
            db.session.rollback()
            return {
                'success': False,
                'message': f'Error disabling 2FA: {str(e)}'
            }
    
    @staticmethod
    def get_user_by_username(username):
        """
        Get user by username
        
        Args:
            username: Username
        
        Returns:
            User object or None
        """
        try:
            return User.query.filter_by(username=username).first()
        except Exception as e:
            logger.error('Error getting user: %s', str(e))
            return None
    
    @staticmethod
    def get_user_by_email(email):
        """
        Get user by email
        
        Args:
            email: Email address
        
        Returns:
            User object or None
        """
        try:
            return User.query.filter_by(email=email).first()
        except Exception as e:
            logger.error('Error getting user: %s', str(e))
            return None
    
    @staticmethod
    def get_user_by_id(user_id):
        """
        Get user by ID
        
        Args:
            user_id: User ID
        
        Returns:
            User object or None
        """
        try:
            return User.query.get(user_id)
        except Exception as e:
            logger.error('Error getting user: %s', str(e))
            return None
