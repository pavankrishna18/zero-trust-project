"""
Threat Intelligence for Zero Trust
Automated threat detection and response
"""

import logging
from datetime import datetime, timezone, timedelta
from models import db, ActivityLog, User, IPWhitelist
import requests

logger = logging.getLogger(__name__)

# Known threat intelligence feeds (free)
ABUSEIPDB_API = "https://api.abuseipdb.com/api/v2/check"
BLOCKLIST_DE = "https://lists.blocklist.de/lists/all.txt"

class ThreatIntelligence:
    """Automated threat detection and response"""
    
    @staticmethod
    def check_ip_reputation(ip_address, api_key=None):
        """
        Check IP reputation against threat databases
        Returns: dict with is_malicious and confidence score
        """
        if ip_address in ['127.0.0.1', 'localhost', '::1']:
            return {'is_malicious': False, 'confidence': 0, 'reports': []}
        
        # Basic check: Too many failed logins
        recent_failures = ActivityLog.query.filter(
            ActivityLog.ip_address == ip_address,
            ActivityLog.action.in_(['login', 'access_denied']),
            ActivityLog.status == 'failed',
            ActivityLog.timestamp >= datetime.now(timezone.utc) - timedelta(hours=1)
        ).count()
        
        if recent_failures >= 10:
            logger.warning('IP %s flagged: %d failed attempts in last hour', 
                         ip_address, recent_failures)
            return {
                'is_malicious': True,
                'confidence': 80,
                'reports': [f'{recent_failures} failed login attempts in last hour']
            }
        
        # If AbuseIPDB API key provided, check external database
        if api_key:
            try:
                headers = {
                    'Key': api_key,
                    'Accept': 'application/json'
                }
                params = {
                    'ipAddress': ip_address,
                    'maxAgeInDays': '90'
                }
                
                response = requests.get(
                    ABUSEIPDB_API,
                    headers=headers,
                    params=params,
                    timeout=5
                )
                
                if response.status_code == 200:
                    data = response.json().get('data', {})
                    abuse_score = data.get('abuseConfidenceScore', 0)
                    
                    if abuse_score > 50:
                        return {
                            'is_malicious': True,
                            'confidence': abuse_score,
                            'reports': [f'AbuseIPDB score: {abuse_score}']
                        }
            except Exception as e:
                logger.error('Threat intelligence API error: %s', str(e))
        
        return {'is_malicious': False, 'confidence': 0, 'reports': []}
    
    @staticmethod
    def detect_brute_force(username, ip_address, time_window_minutes=5):
        """
        Detect brute-force attack
        Returns: True if attack detected
        """
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=time_window_minutes)
        
        failed_attempts = ActivityLog.query.filter(
            ActivityLog.username == username,
            ActivityLog.ip_address == ip_address,
            ActivityLog.action == 'login',
            ActivityLog.status == 'failed',
            ActivityLog.timestamp >= cutoff
        ).count()
        
        if failed_attempts >= 3:
            logger.warning('Brute-force detected: %s from %s (%d attempts in %d minutes)',
                         username, ip_address, failed_attempts, time_window_minutes)
            return True
        
        return False
    
    @staticmethod
    def auto_block_malicious_ip(ip_address, reason):
        """
        Automatically block malicious IP
        Returns: True if blocked
        """
        try:
            # Check if already in whitelist
            existing = IPWhitelist.query.filter_by(ip_address=ip_address).first()
            
            if existing:
                # Disable it
                existing.is_active = False
                existing.description = f"AUTO-BLOCKED: {reason}"
            else:
                # Add as blocked
                blocked_ip = IPWhitelist(
                    ip_address=ip_address,
                    description=f"AUTO-BLOCKED: {reason}",
                    is_active=False,
                    is_range=False
                )
                db.session.add(blocked_ip)
            
            db.session.commit()
            
            logger.info('Auto-blocked IP %s: %s', ip_address, reason)
            
            # Log the action
            ActivityLog.log_activity(
                user_id=0,
                username='SYSTEM',
                action='auto_block_ip',
                status='security_action',
                details=f'Auto-blocked {ip_address}: {reason}'
            )
            
            return True
        except Exception as e:
            logger.error('Auto-block failed for %s: %s', ip_address, str(e))
            db.session.rollback()
            return False
    
    @staticmethod
    def detect_credential_stuffing(username, time_window_hours=1):
        """
        Detect credential stuffing attack
        Multiple failed logins from different IPs
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=time_window_hours)
        
        failed_logins = ActivityLog.query.filter(
            ActivityLog.username == username,
            ActivityLog.action == 'login',
            ActivityLog.status == 'failed',
            ActivityLog.timestamp >= cutoff
        ).all()
        
        # Get unique IPs
        unique_ips = set([log.ip_address for log in failed_logins if log.ip_address])
        
        if len(unique_ips) >= 3 and len(failed_logins) >= 5:
            logger.warning('Credential stuffing detected for %s: %d attempts from %d IPs',
                         username, len(failed_logins), len(unique_ips))
            return True
        
        return False
    
    @staticmethod
    def get_security_alerts(hours=24):
        """Get recent security alerts"""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        
        # Brute-force attempts
        brute_force = ActivityLog.query.filter(
            ActivityLog.action == 'login',
            ActivityLog.status == 'failed',
            ActivityLog.timestamp >= cutoff
        ).count()
        
        # Access denials
        access_denied = ActivityLog.query.filter(
            ActivityLog.action == 'access_denied',
            ActivityLog.timestamp >= cutoff
        ).count()
        
        # IP blocks
        ip_blocks = ActivityLog.query.filter(
            ActivityLog.action.in_(['ip_blocked_realtime', 'auto_block_ip']),
            ActivityLog.timestamp >= cutoff
        ).count()
        
        return {
            'brute_force_attempts': brute_force,
            'access_denials': access_denied,
            'ip_blocks': ip_blocks,
            'time_window': f'{hours} hours'
        }
