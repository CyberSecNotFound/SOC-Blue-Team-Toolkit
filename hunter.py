#!/usr/bin/env python3
import json
from collections import Counter


alerts=json.load(open('data/alerts.json'))


def hunt():
iocs=[a['ioc'] for a in alerts if a.get('ioc')]
counts=Counter(iocs)
for i,c in counts.items():
if c>=3:
print(f'[HUNT] Repeated IOC detected: {i} ({c} alerts)')


if __name__=='__main__':
hunt()
