"""
Risk Scoring Engine for Zero Trust
Calculates risk score based on multiple factors
"""

import logging
from datetime import datetime, timezone, timedelta
from models import db, ActivityLog, Device, User
import ipaddress
from math import radians, cos, sin, asin, sqrt

logger = logging.getLogger(__name__)

class RiskScoringEngine:
    """Calculate risk score for access attempts"""
    
    # Risk score thresholds
    LOW_RISK = 0
    MEDIUM_RISK = 40
    HIGH_RISK = 70
    CRITICAL_RISK = 90
    
    # Risk weights
    WEIGHT_NEW_LOCATION = 30
    WEIGHT_UNUSUAL_TIME = 20
    WEIGHT_NEW_DEVICE = 25
    WEIGHT_FAILED_ATTEMPTS = 25
    WEIGHT_VELOCITY = 35
    WEIGHT_TOR_VPN = 40
    WEIGHT_SUSPICIOUS_COUNTRY = 30
    
    @staticmethod
    def calculate_risk_score(user, client_ip, user_agent, device=None):
        """
        Calculate comprehensive risk score
        Returns: dict with score and reasons
        """
        risk_score = 0
        risk_factors = []
        
        # 1. Check for new location
        location_risk = RiskScoringEngine._check_location_risk(user, client_ip)
        risk_score += location_risk['score']
        if location_risk['factor']:
            risk_factors.append(location_risk['factor'])
        
        # 2. Check for unusual time
        time_risk = RiskScoringEngine._check_time_risk(user)
        risk_score += time_risk['score']
        if time_risk['factor']:
            risk_factors.append(time_risk['factor'])
        
        # 3. Check for new device
        device_risk = RiskScoringEngine._check_device_risk(user, device)
        risk_score += device_risk['score']
        if device_risk['factor']:
            risk_factors.append(device_risk['factor'])
        
        # 4. Check for failed login attempts
        failed_risk = RiskScoringEngine._check_failed_attempts(user)
        risk_score += failed_risk['score']
        if failed_risk['factor']:
            risk_factors.append(failed_risk['factor'])
        
        # 5. Check for impossible travel (velocity)
        velocity_risk = RiskScoringEngine._check_velocity(user, client_ip)
        risk_score += velocity_risk['score']
        if velocity_risk['factor']:
            risk_factors.append(velocity_risk['factor'])
        
        # Determine risk level
        if risk_score >= RiskScoringEngine.CRITICAL_RISK:
            risk_level = 'CRITICAL'
        elif risk_score >= RiskScoringEngine.HIGH_RISK:
            risk_level = 'HIGH'
        elif risk_score >= RiskScoringEngine.MEDIUM_RISK:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        logger.info('Risk score for %s: %d (%s) - Factors: %s', 
                   user.username, risk_score, risk_level, risk_factors)
        
        return {
            'score': risk_score,
            'level': risk_level,
            'factors': risk_factors,
            'requires_additional_verification': risk_score >= RiskScoringEngine.MEDIUM_RISK
        }
    
    @staticmethod
    def _check_location_risk(user, client_ip):
        """Check if login from new location"""
        try:
            # Get user's recent login locations (last 30 days)
            thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
            recent_activities = ActivityLog.query.filter(
                ActivityLog.user_id == user.id,
                ActivityLog.action == 'login',
                ActivityLog.timestamp >= thirty_days_ago
            ).all()
            
            known_ips = set([activity.ip_address for activity in recent_activities if activity.ip_address])
            
            if client_ip not in known_ips:
                return {'score': RiskScoringEngine.WEIGHT_NEW_LOCATION, 
                       'factor': 'New location detected'}
        except Exception as e:
            logger.error('Location risk check error: %s', str(e))
        
        return {'score': 0, 'factor': None}
    
    @staticmethod
    def _check_time_risk(user):
        """Check if login at unusual time"""
        try:
            current_hour = datetime.now(timezone.utc).hour
            
            # Get user's typical login hours
            recent_activities = ActivityLog.query.filter(
                ActivityLog.user_id == user.id,
                ActivityLog.action == 'login'
            ).limit(50).all()
            
            if recent_activities:
                typical_hours = [activity.timestamp.hour for activity in recent_activities]
                avg_hour = sum(typical_hours) / len(typical_hours)
                
                # If current hour differs by more than 4 hours from average
                if abs(current_hour - avg_hour) > 4:
                    return {'score': RiskScoringEngine.WEIGHT_UNUSUAL_TIME, 
                           'factor': 'Unusual login time'}
        except Exception as e:
            logger.error('Time risk check error: %s', str(e))
        
        return {'score': 0, 'factor': None}
    
    @staticmethod
    def _check_device_risk(user, device):
        """Check if new device"""
        try:
            if device and not device.is_trusted:
                return {'score': RiskScoringEngine.WEIGHT_NEW_DEVICE, 
                       'factor': 'New unverified device'}
            
            # Check if user has any trusted devices
            trusted_count = Device.query.filter_by(user_id=user.id, is_trusted=True).count()
            if trusted_count == 0:
                return {'score': RiskScoringEngine.WEIGHT_NEW_DEVICE // 2, 
                       'factor': 'First device registration'}
        except Exception as e:
            logger.error('Device risk check error: %s', str(e))
        
        return {'score': 0, 'factor': None}
    
    @staticmethod
    def _check_failed_attempts(user):
        """Check recent failed login attempts"""
        try:
            if user.failed_login_attempts >= 3:
                return {'score': RiskScoringEngine.WEIGHT_FAILED_ATTEMPTS, 
                       'factor': f'{user.failed_login_attempts} failed login attempts'}
        except Exception as e:
            logger.error('Failed attempts check error: %s', str(e))
        
        return {'score': 0, 'factor': None}
    
    @staticmethod
    def _check_velocity(user, client_ip):
        """Check for impossible travel (velocity attack)"""
        try:
            # Get last login location and time
            last_activity = ActivityLog.query.filter(
                ActivityLog.user_id == user.id,
                ActivityLog.action == 'login',
                ActivityLog.status == 'success'
            ).order_by(ActivityLog.timestamp.desc()).first()
            
            if last_activity and last_activity.ip_address:
                time_diff = (datetime.now(timezone.utc) - last_activity.timestamp).total_seconds() / 3600  # hours
                
                # If login within last hour from different IP (basic check)
                if time_diff < 1 and last_activity.ip_address != client_ip:
                    return {'score': RiskScoringEngine.WEIGHT_VELOCITY, 
                           'factor': 'Rapid location change detected'}
        except Exception as e:
            logger.error('Velocity check error: %s', str(e))
        
        return {'score': 0, 'factor': None}
    
    @staticmethod
    def log_risk_assessment(user_id, username, risk_data):
        """Log risk assessment result"""
        try:
            ActivityLog.log_activity(
                user_id,
                username,
                'risk_assessment',
                'info',
                f"Risk: {risk_data['level']} (Score: {risk_data['score']}) - {', '.join(risk_data['factors']) if risk_data['factors'] else 'No risk factors'}"
            )
        except:
            pass
