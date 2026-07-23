"""
Test Data Generator for ZeroTrustX
Generates sample security events for testing
"""

from app import app
from models import db, User, RiskAssessment, LoginHistory, ThreatEvent, IPWhitelist
from datetime import datetime, timezone, timedelta
import random

def generate_test_data():
    """Generate test security data"""
    with app.app_context():
        print("🔄 Generating test security data...")
        
        # Get admin user
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            print("❌ Admin user not found. Please create admin first.")
            return
        
        # 1. Generate Risk Assessments
        print("📊 Creating risk assessments...")
        risk_levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        for i in range(15):
            score = random.randint(0, 100)
            if score < 30:
                level = 'LOW'
            elif score < 50:
                level = 'MEDIUM'
            elif score < 70:
                level = 'HIGH'
            else:
                level = 'CRITICAL'
            
            risk = RiskAssessment(
                user_id=admin.id,
                risk_score=score,
                risk_level=level,
                risk_factors='["new_location", "unusual_time", "unknown_device"]',
                action='login',
                ip_address=f'192.168.1.{random.randint(1, 255)}',
                location_country='US',
                location_city='New York',
                additional_verification_required=score >= 70,
                was_blocked=score >= 90,
                created_at=datetime.now(timezone.utc) - timedelta(hours=random.randint(0, 24))
            )
            db.session.add(risk)
        
        # 2. Generate Threat Events
        print("🐛 Creating threat events...")
        threat_types = ['brute_force', 'suspicious_login', 'blocked_country', 'vpn_detected']
        severities = ['low', 'medium', 'high', 'critical']
        
        for i in range(10):
            threat = ThreatEvent(
                threat_type=random.choice(threat_types),
                severity=random.choice(severities),
                description='Suspicious activity detected from unusual location',
                source_ip=f'203.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}',
                source_country=random.choice(['CN', 'RU', 'US', 'UK', 'IN']),
                target_user_id=admin.id,
                target_username='admin',
                was_blocked=random.choice([True, False]),
                auto_blocked=random.choice([True, False]),
                detected_at=datetime.now(timezone.utc) - timedelta(days=random.randint(0, 7))
            )
            db.session.add(threat)
        
        # 3. Generate Login History
        print("🌍 Creating login history...")
        countries = [
            ('United States', 'US', 'New York'),
            ('United Kingdom', 'GB', 'London'),
            ('India', 'IN', 'Mumbai'),
            ('Germany', 'DE', 'Berlin'),
            ('Japan', 'JP', 'Tokyo')
        ]
        
        for i in range(20):
            country, code, city = random.choice(countries)
            login = LoginHistory(
                user_id=admin.id,
                ip_address=f'{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}',
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
                country=country,
                country_code=code,
                city=city,
                latitude=random.uniform(-90, 90),
                longitude=random.uniform(-180, 180),
                isp='Example ISP',
                is_proxy=random.choice([True, False]),
                success=random.choice([True, True, True, False]),  # 75% success rate
                failure_reason='Invalid credentials' if random.random() > 0.75 else None,
                risk_score=random.randint(0, 100),
                is_suspicious=random.random() > 0.8,
                timestamp=datetime.now(timezone.utc) - timedelta(days=random.randint(0, 7))
            )
            db.session.add(login)
        
        # 4. Add some blocked IPs
        print("🚫 Creating blocked IPs...")
        for i in range(5):
            ip = IPWhitelist(
                ip_address=f'192.168.{random.randint(100,200)}.{random.randint(1,255)}',
                description='Auto-blocked due to suspicious activity',
                is_active=False,
                is_auto_blocked=True,
                block_reason='Brute-force attack detected',
                blocked_at=datetime.now(timezone.utc) - timedelta(hours=random.randint(1, 48))
            )
            db.session.add(ip)
        
        # Commit all changes
        db.session.commit()
        
        print("✅ Test data generated successfully!")
        print("\n📊 Summary:")
        print(f"  • Risk Assessments: {RiskAssessment.query.count()}")
        print(f"  • Threat Events: {ThreatEvent.query.count()}")
        print(f"  • Login History: {LoginHistory.query.count()}")
        print(f"  • Blocked IPs: {IPWhitelist.query.filter_by(is_auto_blocked=True).count()}")
        print("\n🎉 Refresh your Security Analytics page to see the data!")

if __name__ == '__main__':
    generate_test_data()
