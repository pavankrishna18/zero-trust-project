import os

files = ['app.py', 'auth.py', 'models.py', 'monitoring.py', 'device_trust.py']

for fname in files:
    try:
        with open(fname, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        # Add timezone import to datetime line
        new_lines = []
        for line in lines:
            if 'from datetime import' in line and 'timezone' not in line:
                line = line.rstrip()
                if line.endswith(')'):
                    line = line[:-1] + ', timezone)'
                else:
                    line = line + ', timezone'
                line += '\n'
            new_lines.append(line)
        
        # Replace utcnow
        content = ''.join(new_lines)
        content = content.replace('datetime.utcnow()', 'datetime.now(timezone.utc)')
        
        with open(fname, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f"✅ Fixed {fname}")
    except Exception as e:
        print(f"❌ {fname}: {e}")
