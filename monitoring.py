"""
Monitoring and Security Metrics Service
Provides real-time security monitoring, activity tracking, and analytics
"""

from models import db, User, Device, Session, ActivityLog
from datetime import datetime, timezone, timedelta
from sqlalchemy import func, and_, or_

class MonitoringService:
    """Service for monitoring system activity and security metrics"""

    @staticmethod
    def calculate_security_score():
        """
        Derive a 0-100 organizational security score from current signals.
        Starts at 100 and deducts points for active risk indicators.
        Returns a dict with the score, letter grade, and the factors used.
        """
        try:
            metrics = MonitoringService.get_security_metrics()

            score = 100
            factors = []

            untrusted = metrics.get('untrusted_devices', 0)
            deduction = min(untrusted * 4, 25)
            if deduction:
                score -= deduction
                factors.append({'label': f'{untrusted} untrusted device(s)', 'impact': -deduction})

            locked = metrics.get('locked_users', 0)
            deduction = min(locked * 5, 15)
            if deduction:
                score -= deduction
                factors.append({'label': f'{locked} locked account(s)', 'impact': -deduction})

            failed = metrics.get('failed_logins_24h', 0)
            deduction = min(failed * 2, 25)
            if deduction:
                score -= deduction
                factors.append({'label': f'{failed} failed login(s) in 24h', 'impact': -deduction})

            denials = metrics.get('access_denials_24h', 0)
            deduction = min(denials * 3, 20)
            if deduction:
                score -= deduction
                factors.append({'label': f'{denials} access denial(s) in 24h', 'impact': -deduction})

            try:
                from models import ThreatEvent
                unblocked_threats = ThreatEvent.query.filter_by(was_blocked=False).filter(
                    ThreatEvent.detected_at >= datetime.now(timezone.utc) - timedelta(hours=24)
                ).count()
                deduction = min(unblocked_threats * 6, 20)
                if deduction:
                    score -= deduction
                    factors.append({'label': f'{unblocked_threats} unresolved threat(s)', 'impact': -deduction})
            except Exception:
                pass

            score = max(0, min(100, score))

            if score >= 90:
                grade, level = 'A', 'excellent'
            elif score >= 75:
                grade, level = 'B', 'good'
            elif score >= 60:
                grade, level = 'C', 'fair'
            elif score >= 40:
                grade, level = 'D', 'weak'
            else:
                grade, level = 'F', 'critical'

            if not factors:
                factors.append({'label': 'No active risk indicators', 'impact': 0})

            return {
                'score': score,
                'grade': grade,
                'level': level,
                'factors': factors
            }
        except Exception as e:
            print(f'Error calculating security score: {str(e)}')
            return {'score': 0, 'grade': 'N/A', 'level': 'unknown', 'factors': []}

    @staticmethod
    def get_ai_recommendations(limit=5):
        """
        Rule-based recommendation engine derived from current security signals.
        Not an actual LLM call — deterministic heuristics over live metrics,
        ordered by severity so the highest-impact action surfaces first.
        """
        try:
            metrics = MonitoringService.get_security_metrics()
            recs = []

            if metrics.get('untrusted_devices', 0) > 0:
                recs.append({
                    'severity': 'warning',
                    'title': 'Review untrusted devices',
                    'detail': f"{metrics['untrusted_devices']} device(s) are awaiting trust approval. Review and approve or revoke them.",
                    'action_label': 'Go to Devices',
                    'action_endpoint': 'device_management'
                })

            if metrics.get('locked_users', 0) > 0:
                recs.append({
                    'severity': 'danger',
                    'title': 'Locked accounts need attention',
                    'detail': f"{metrics['locked_users']} account(s) are currently locked, likely from repeated failed logins. Verify these aren't active brute-force attempts.",
                    'action_label': 'Go to Users',
                    'action_endpoint': 'manage_users'
                })

            if metrics.get('failed_logins_24h', 0) >= 5:
                recs.append({
                    'severity': 'danger',
                    'title': 'Elevated failed login activity',
                    'detail': f"{metrics['failed_logins_24h']} failed logins in the last 24 hours. Consider tightening rate limits or reviewing source IPs.",
                    'action_label': 'View Threats',
                    'action_endpoint': 'security_analytics'
                })
            elif metrics.get('failed_logins_24h', 0) > 0:
                recs.append({
                    'severity': 'info',
                    'title': 'Some failed login attempts detected',
                    'detail': f"{metrics['failed_logins_24h']} failed login(s) in the last 24 hours. Within normal range, but worth a glance.",
                    'action_label': 'View Threats',
                    'action_endpoint': 'security_analytics'
                })

            if metrics.get('access_denials_24h', 0) > 0:
                recs.append({
                    'severity': 'warning',
                    'title': 'Access policy denials occurring',
                    'detail': f"{metrics['access_denials_24h']} requests were denied by access policy in the last 24 hours. Confirm these are expected.",
                    'action_label': 'Review Policies',
                    'action_endpoint': 'manage_policies'
                })

            try:
                from models import ThreatEvent
                unblocked = ThreatEvent.query.filter_by(was_blocked=False, is_investigated=False).filter(
                    ThreatEvent.detected_at >= datetime.now(timezone.utc) - timedelta(hours=24)
                ).count()
                if unblocked > 0:
                    recs.append({
                        'severity': 'danger',
                        'title': 'Unresolved threat events',
                        'detail': f"{unblocked} threat event(s) from the last 24h have not been investigated or blocked.",
                        'action_label': 'Investigate',
                        'action_endpoint': 'security_analytics'
                    })
            except Exception:
                pass

            if not recs:
                recs.append({
                    'severity': 'success',
                    'title': 'No action needed',
                    'detail': 'All current signals are within normal range. Keep monitoring as usual.',
                    'action_label': None,
                    'action_endpoint': None
                })

            severity_order = {'danger': 0, 'warning': 1, 'info': 2, 'success': 3}
            recs.sort(key=lambda r: severity_order.get(r['severity'], 9))

            return recs[:limit]
        except Exception as e:
            print(f'Error generating recommendations: {str(e)}')
            return []

    @staticmethod
    def get_security_metrics():
        """Get current security metrics"""
        try:
            total_users = User.query.count()
            active_sessions = Session.query.filter_by(is_active=True).count()
            untrusted_devices = Device.query.filter_by(is_trusted=False).count()
            locked_users = User.query.filter_by(is_locked=True).count()
            
            # Failed logins in last 24 hours
            yesterday = datetime.now(timezone.utc) - timedelta(days=1)
            failed_logins_24h = ActivityLog.query.filter(
                and_(
                    ActivityLog.status == 'failed',
                    ActivityLog.timestamp >= yesterday
                )
            ).count()
            
            # Access denials in last 24 hours
            access_denials_24h = ActivityLog.query.filter(
                and_(
                    ActivityLog.status == 'denied',
                    ActivityLog.timestamp >= yesterday
                )
            ).count()
            
            return {
                'total_users': total_users,
                'active_sessions': active_sessions,
                'untrusted_devices': untrusted_devices,
                'locked_users': locked_users,
                'failed_logins_24h': failed_logins_24h,
                'access_denials_24h': access_denials_24h,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        except Exception as e:
            print(f'Error getting security metrics: {str(e)}')
            return {
                'total_users': 0,
                'active_sessions': 0,
                'untrusted_devices': 0,
                'locked_users': 0,
                'failed_logins_24h': 0,
                'access_denials_24h': 0,
            }
    
    @staticmethod
    def get_recent_activities(limit=50):
        """Get recent system activities"""
        try:
            activities = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(limit).all()
            return [activity.to_dict() for activity in activities]
        except Exception as e:
            print(f'Error getting recent activities: {str(e)}')
            return []
    
    @staticmethod
    def get_user_activities(user_id, limit=50):
        """Get activities for a specific user"""
        try:
            activities = ActivityLog.query.filter_by(user_id=user_id).order_by(
                ActivityLog.timestamp.desc()
            ).limit(limit).all()
            return [activity.to_dict() for activity in activities]
        except Exception as e:
            print(f'Error getting user activities: {str(e)}')
            return []
    
    @staticmethod
    def get_active_sessions(limit=50):
        """Get all active sessions"""
        try:
            sessions = Session.query.filter_by(is_active=True).order_by(
                Session.created_at.desc()
            ).limit(limit).all()
            return [session.to_dict() for session in sessions]
        except Exception as e:
            print(f'Error getting active sessions: {str(e)}')
            return []
    
    @staticmethod
    def get_access_denials_24h():
        """Get access denials in last 24 hours"""
        try:
            yesterday = datetime.now(timezone.utc) - timedelta(days=1)
            denials = ActivityLog.query.filter(
                and_(
                    ActivityLog.status == 'denied',
                    ActivityLog.timestamp >= yesterday
                )
            ).all()
            return [denial.to_dict() for denial in denials]
        except Exception as e:
            print(f'Error getting access denials: {str(e)}')
            return []
    
    @staticmethod
    def get_failed_logins_24h():
        """Get failed login attempts in last 24 hours"""
        try:
            yesterday = datetime.now(timezone.utc) - timedelta(days=1)
            failed = ActivityLog.query.filter(
                and_(
                    ActivityLog.action == 'login',
                    ActivityLog.status == 'failed',
                    ActivityLog.timestamp >= yesterday
                )
            ).all()
            return [log.to_dict() for log in failed]
        except Exception as e:
            print(f'Error getting failed logins: {str(e)}')
            return []
    
    @staticmethod
    def get_device_registration_stats():
        """Get device registration statistics"""
        try:
            total_devices = Device.query.count()
            trusted_devices = Device.query.filter_by(is_trusted=True).count()
            untrusted_devices = Device.query.filter_by(is_trusted=False).count()
            
            return {
                'total_devices': total_devices,
                'trusted_devices': trusted_devices,
                'untrusted_devices': untrusted_devices,
            }
        except Exception as e:
            print(f'Error getting device stats: {str(e)}')
            return {}
    
    @staticmethod
    def get_activity_summary_by_action(days=7):
        """Get activity summary grouped by action"""
        try:
            since = datetime.now(timezone.utc) - timedelta(days=days)
            
            activities = db.session.query(
                ActivityLog.action,
                func.count(ActivityLog.id).label('count'),
                ActivityLog.status
            ).filter(
                ActivityLog.timestamp >= since
            ).group_by(
                ActivityLog.action,
                ActivityLog.status
            ).all()
            
            return [
                {
                    'action': activity[0],
                    'count': activity[1],
                    'status': activity[2]
                }
                for activity in activities
            ]
        except Exception as e:
            print(f'Error getting activity summary: {str(e)}')
            return []
    
    @staticmethod
    def get_high_risk_activities(limit=50):
        """Get high-risk activities (failed logins, access denials, etc.)"""
        try:
            high_risk_statuses = ['failed', 'denied', 'warning']
            activities = ActivityLog.query.filter(
                ActivityLog.status.in_(high_risk_statuses)
            ).order_by(
                ActivityLog.timestamp.desc()
            ).limit(limit).all()
            
            return [activity.to_dict() for activity in activities]
        except Exception as e:
            print(f'Error getting high-risk activities: {str(e)}')
            return []
    
    @staticmethod
    def get_user_login_stats(user_id):
        """Get login statistics for a user"""
        try:
            user = User.query.get(user_id)
            if not user:
                return {}
            
            yesterday = datetime.now(timezone.utc) - timedelta(days=1)
            
            successful_logins_24h = ActivityLog.query.filter(
                and_(
                    ActivityLog.user_id == user_id,
                    ActivityLog.action == 'login',
                    ActivityLog.status == 'success',
                    ActivityLog.timestamp >= yesterday
                )
            ).count()
            
            failed_logins_24h = ActivityLog.query.filter(
                and_(
                    ActivityLog.user_id == user_id,
                    ActivityLog.action == 'login',
                    ActivityLog.status == 'failed',
                    ActivityLog.timestamp >= yesterday
                )
            ).count()
            
            return {
                'username': user.username,
                'last_login': user.last_login.isoformat() if user.last_login else None,
                'successful_logins_24h': successful_logins_24h,
                'failed_logins_24h': failed_logins_24h,
                'is_locked': user.is_locked,
                'failed_attempts': user.failed_login_attempts,
            }
        except Exception as e:
            print(f'Error getting user login stats: {str(e)}')
            return {}
    
    @staticmethod
    def log_access_control_decision(user_id, username, resource, action, allowed, reason):
        """Log access control decision"""
        try:
            activity = ActivityLog(
                user_id=user_id,
                username=username,
                action=f'access_control_{action}',
                status='success' if allowed else 'denied',
                details=f'Resource: {resource}, Reason: {reason}',
                resource_accessed=resource,
                timestamp=datetime.now(timezone.utc)
            )
            db.session.add(activity)
            db.session.commit()
        except Exception as e:
            print(f'Error logging access control decision: {str(e)}')
