"""
Device Trust Service
Handles device registration, fingerprinting, and trust management
"""

from models import db, Device, User
from datetime import datetime, timezone
import hashlib
import json
import logging

logger = logging.getLogger(__name__)

class DeviceTrustService:
    """Service for managing device trust"""
    
    @staticmethod
    def generate_device_fingerprint(user_id, ip_address, user_agent):
        """Generate unique device fingerprint"""
        try:
            fingerprint_data = f"{user_id}:{ip_address}:{user_agent}"
            fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()
            return fingerprint
        except Exception as e:
            logger.error('Error generating device fingerprint: %s', str(e))
            return None
    
    @staticmethod
    def parse_user_agent(user_agent):
        """Parse user agent to extract browser and OS info"""
        try:
            user_agent = user_agent.lower()
            
            # Detect OS
            os_name = 'Unknown'
            if 'windows' in user_agent:
                os_name = 'Windows'
            elif 'mac' in user_agent:
                os_name = 'macOS'
            elif 'linux' in user_agent:
                os_name = 'Linux'
            elif 'iphone' in user_agent:
                os_name = 'iOS'
            elif 'android' in user_agent:
                os_name = 'Android'
            
            # Detect Browser
            browser_name = 'Unknown'
            if 'chrome' in user_agent and 'edge' not in user_agent:
                browser_name = 'Chrome'
            elif 'safari' in user_agent and 'chrome' not in user_agent:
                browser_name = 'Safari'
            elif 'firefox' in user_agent:
                browser_name = 'Firefox'
            elif 'edge' in user_agent:
                browser_name = 'Edge'
            elif 'opera' in user_agent:
                browser_name = 'Opera'
            
            return {
                'browser': browser_name,
                'os': os_name
            }
        except Exception as e:
            logger.error('Error parsing user agent: %s', str(e))
            return {'browser': 'Unknown', 'os': 'Unknown'}
    
    @staticmethod
    def register_device(user_id, ip_address='127.0.0.1', user_agent='Unknown'):
        """Register a device for a user"""
        try:
            user = db.session.get(User, user_id)
            if not user:
                return {'success': False, 'message': 'User not found'}
            
            # Generate fingerprint
            fingerprint = DeviceTrustService.generate_device_fingerprint(user_id, ip_address, user_agent)
            if not fingerprint:
                return {'success': False, 'message': 'Failed to generate device fingerprint'}
            
            # Check if device already exists
            device = Device.query.filter_by(device_fingerprint=fingerprint).first()
            
            if device:
                # Update last_used timestamp (NOT last_seen!)
                device.last_used = datetime.now(timezone.utc)
                db.session.commit()
                logger.info('Device %s already registered, updated last_used', fingerprint[:10])
                return {
                    'success': True,
                    'device': device,
                    'new_device': False,
                    'message': 'Device already registered'
                }
            else:
                # Parse user agent
                ua_info = DeviceTrustService.parse_user_agent(user_agent)
                
                # Create new device
                new_device = Device(
                    user_id=user_id,
                    device_fingerprint=fingerprint,
                    device_name=f"{ua_info['browser']} on {ua_info['os']}",
                    browser=ua_info['browser'],
                    os=ua_info['os'],
                    ip_address=ip_address,
                    user_agent=user_agent,
                    is_trusted=False,
                    trust_score=0,
                    created_at=datetime.now(timezone.utc),
                    last_used=datetime.now(timezone.utc)  # NOT last_seen!
                )
                
                db.session.add(new_device)
                db.session.commit()
                
                logger.info('New device registered for user %s: %s', user.username, fingerprint[:10])
                return {
                    'success': True,
                    'device': new_device,
                    'new_device': True,
                    'message': 'Device registered successfully'
                }
        
        except Exception as e:
            logger.error('Error registering device: %s', str(e))
            db.session.rollback()
            return {
                'success': False,
                'message': f'Error registering device: {str(e)}'
            }
    
    @staticmethod
    def trust_device(device_id):
        """Mark device as trusted"""
        try:
            device = db.session.get(Device, device_id)
            if not device:
                return {'success': False, 'message': 'Device not found'}
            
            device.is_trusted = True
            device.trust_score = 100
            device.trusted_at = datetime.now(timezone.utc)
            device.last_used = datetime.now(timezone.utc)
            
            db.session.commit()
            
            logger.info('Device %s marked as trusted', device_id)
            return {'success': True, 'message': 'Device trusted successfully'}
        
        except Exception as e:
            logger.error('Error trusting device: %s', str(e))
            db.session.rollback()
            return {'success': False, 'message': f'Error trusting device: {str(e)}'}
    
    @staticmethod
    def revoke_device_trust(device_id):
        """Revoke device trust"""
        try:
            device = db.session.get(Device, device_id)
            if not device:
                return {'success': False, 'message': 'Device not found'}
            
            device.is_trusted = False
            device.trust_score = 0
            device.trusted_at = None
            
            db.session.commit()
            
            logger.info('Device %s trust revoked', device_id)
            return {'success': True, 'message': 'Device trust revoked successfully'}
        
        except Exception as e:
            logger.error('Error revoking device trust: %s', str(e))
            db.session.rollback()
            return {'success': False, 'message': f'Error revoking device trust: {str(e)}'}
    
    @staticmethod
    def get_user_devices(user_id):
        """Get all devices for a user"""
        try:
            devices = Device.query.filter_by(user_id=user_id).all()
            return devices
        except Exception as e:
            logger.error('Error getting user devices: %s', str(e))
            return []
    
    @staticmethod
    def get_trusted_devices_count(user_id):
        """Get count of trusted devices for a user"""
        try:
            count = Device.query.filter_by(user_id=user_id, is_trusted=True).count()
            return count
        except Exception as e:
            logger.error('Error getting trusted devices count: %s', str(e))
            return 0
    
    @staticmethod
    def check_device_trust_status(device_id):
        """Check if device is trusted"""
        try:
            device = db.session.get(Device, device_id)
            if not device:
                return False
            return device.is_trusted
        except Exception as e:
            logger.error('Error checking device trust status: %s', str(e))
            return False
    
    @staticmethod
    def update_device_activity(device_id, ip_address=None):
        """Update device last activity timestamp"""
        try:
            device = db.session.get(Device, device_id)
            if not device:
                return {'success': False, 'message': 'Device not found'}
            
            device.last_used = datetime.now(timezone.utc)
            if ip_address:
                device.ip_address = ip_address
            
            db.session.commit()
            return {'success': True, 'message': 'Device activity updated'}
        
        except Exception as e:
            logger.error('Error updating device activity: %s', str(e))
            db.session.rollback()
            return {'success': False, 'message': f'Error updating device activity: {str(e)}'}
