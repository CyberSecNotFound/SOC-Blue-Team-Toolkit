#!/usr/bin/env python3
import os
import json
import hashlib
import subprocess
from datetime import datetime
from mitre import MITRE_MAP

DATA_DIR = 'data'
CONFIG_DIR = 'config'

ALERT_FILE = f'{DATA_DIR}/alerts.json'
FIM_DB_FILE = f'{DATA_DIR}/fim_db.json'
FIM_TARGETS = f'{CONFIG_DIR}/fim_targets.txt'

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(CONFIG_DIR, exist_ok=True)

# Load alerts
if os.path.exists(ALERT_FILE):
    with open(ALERT_FILE, 'r') as f:
        alerts = json.load(f)
else:
    alerts = []

def raise_alert(code, message, ioc=None, severity='HIGH'):
    alert = {
        'time': datetime.utcnow().isoformat(),
        'severity': severity,
        'message': message,
        'ioc': ioc,
        'mitre': MITRE_MAP.get(code)
    }
    alerts.append(alert)

# --- SSH Brute Force Detection ---
def detect_ssh_bruteforce():
    log_file = '/var/log/auth.log'
    if not os.path.exists(log_file):
        return

    attempts = {}
    with open(log_file, 'r') as f:
        for line in f:
            if 'Failed password' in line:
                ip = line.split()[-4]
                attempts[ip] = attempts.get(ip, 0) + 1

    for ip, count in attempts.items():
        if count >= 5:
            raise_alert(
                'SSH_BRUTE',
                f'SSH brute force detected ({count} attempts)',
                ip
            )

# --- Insecure Service Detection ---
def detect_insecure_services():
    output = subprocess.getoutput('netstat -tulnp')
    for line in output.splitlines():
        if ':21' in line or ':23' in line:
            raise_alert(
                'INSECURE_SERVICE',
                'FTP/Telnet service exposed',
                line
            )

# --- File Integrity Monitoring ---
def file_integrity_monitoring():
    if os.path.exists(FIM_DB_FILE):
        with open(FIM_DB_FILE, 'r') as f:
            baseline = json.load(f)
    else:
        baseline = {}

    if not os.path.exists(FIM_TARGETS):
        return

    with open(FIM_TARGETS, 'r') as f:
        for filepath in f:
            filepath = filepath.strip()
            if os.path.exists(filepath):
                with open(filepath, 'rb') as target:
                    file_hash = hashlib.sha256(target.read()).hexdigest()

                if filepath in baseline and baseline[filepath] != file_hash:
                    raise_alert(
                        'FILE_TAMPERING',
                        'Critical file modified',
                        filepath,
                        severity='CRITICAL'
                    )
                baseline[filepath] = file_hash

    with open(FIM_DB_FILE, 'w') as f:
        json.dump(baseline, f, indent=2)

def save_alerts():
    with open(ALERT_FILE, 'w') as f:
        json.dump(alerts, f, indent=2)

if __name__ == '__main__':
    detect_ssh_bruteforce()
    detect_insecure_services()
    file_integrity_monitoring()
    save_alerts()
    print('[+] SOC detection cycle completed')
