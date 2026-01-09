#!/usr/bin/env python3
import json
from collections import Counter
import os

ALERT_FILE = 'data/alerts.json'

if not os.path.exists(ALERT_FILE):
    print('[-] No alert data found')
    exit(0)

with open(ALERT_FILE, 'r') as f:
    alerts = json.load(f)

def hunt_repeated_ioc():
    iocs = [a['ioc'] for a in alerts if a.get('ioc')]
    counts = Counter(iocs)

    for ioc, count in counts.items():
        if count >= 3:
            print(f'[HUNT] Repeated IOC detected: {ioc} ({count} alerts)')

if __name__ == '__main__':
    hunt_repeated_ioc()
