from app import app, db
from models import User, Device, AccessPolicy, ActivityLog, Session
from tabulate import tabulate

with app.app_context():
    print("\n" + "="*80)
    print("🗄️  ZEROTRUST DATABASE VIEWER")
    print("="*80)
    
    # View Users
    print("\n📊 USERS:")
    users = User.query.all()
    user_data = [[u.id, u.username, u.email, u.role, u.is_active, u.is_locked] 
                 for u in users]
    print(tabulate(user_data, headers=['ID', 'Username', 'Email', 'Role', 'Active', 'Locked']))
    
    # View Devices
    print("\n📱 DEVICES:")
    devices = Device.query.all()
    device_data = [[d.id, d.user.username, d.browser, d.os, d.ip_address, d.is_trusted] 
                   for d in devices]
    print(tabulate(device_data, headers=['ID', 'User', 'Browser', 'OS', 'IP', 'Trusted']))
    
    # View Access Policies
    print("\n🔐 ACCESS POLICIES:")
    policies = AccessPolicy.query.all()
    policy_data = [[p.id, p.name, p.role, p.resource, p.action, p.is_active] 
                   for p in policies]
    print(tabulate(policy_data, headers=['ID', 'Name', 'Role', 'Resource', 'Action', 'Active']))
    
    # View Recent Activity (last 10)
    print("\n📝 RECENT ACTIVITIES (Last 10):")
    activities = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(10).all()
    activity_data = [[a.username, a.action, a.status, a.ip_address, 
                     a.timestamp.strftime('%Y-%m-%d %H:%M:%S')] 
                    for a in activities]
    print(tabulate(activity_data, headers=['User', 'Action', 'Status', 'IP', 'Time']))
    
    # View Active Sessions
    print("\n🔑 ACTIVE SESSIONS:")
    sessions = Session.query.filter_by(is_active=True).all()
    session_data = [[s.id, s.user.username, s.ip_address, 
                    s.created_at.strftime('%Y-%m-%d %H:%M:%S')] 
                   for s in sessions]
    print(tabulate(session_data, headers=['ID', 'User', 'IP', 'Created']))
    
    print("\n" + "="*80)
