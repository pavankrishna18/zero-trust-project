import os
import re

files_to_fix = [
    'app.py',
    'auth.py',
    'models.py',
    'monitoring.py',
    'device_trust.py'
]

for file in files_to_fix:
    if os.path.exists(file):
        try:
            # Read with UTF-8 encoding
            with open(file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Add timezone import if not present
            if 'from datetime import' in content and 'timezone' not in content:
                content = content.replace(
                    'from datetime import datetime, timedelta',
                    'from datetime import datetime, timedelta, timezone'
                )
                # Also handle case with just datetime
                content = content.replace(
                    'from datetime import datetime',
                    'from datetime import datetime, timezone'
                )
            
            # Replace utcnow() with now(timezone.utc)
            content = content.replace('datetime.utcnow()', 'datetime.now(timezone.utc)')
            
            # Write with UTF-8 encoding
            with open(file, 'w', encoding='utf-8') as f:
                f.write(content)
            
            print(f"✅ Fixed {file}")
        
        except Exception as e:
            print(f"❌ Error fixing {file}: {e}")
    else:
        print(f"⚠️ File not found: {file}")

print("\n✅ All datetime.utcnow() calls fixed!")
