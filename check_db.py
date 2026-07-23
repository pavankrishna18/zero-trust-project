from app import app, db
from models import User

with app.app_context():
    # Check all users
    users = User.query.all()
    print(f"\n📊 Total users in database: {len(users)}\n")
    
    for user in users:
        print(f"Username: {user.username}")
        print(f"Email: {user.email}")
        print(f"Role: {user.role}")
        print(f"OTP Secret: {user.otp_secret}")
        print("-" * 50)
    
    # Check admin specifically
    admin = User.query.filter_by(username='admin').first()
    if admin:
        print("\n✅ Admin user EXISTS")
        print(f"Password hash: {admin.password_hash[:50]}...")
    else:
        print("\n❌ Admin user NOT FOUND")
