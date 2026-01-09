#!/usr/bin/env python3


alerts = json.load(open(ALERT_FILE)) if os.path.exists(ALERT_FILE) else []


def alert(code, msg, ioc=None, severity='HIGH'):
alerts.append({
'time': datetime.utcnow().isoformat(),
'severity': severity,
'message': msg,
'ioc': ioc,
'mitre': MITRE_MAP.get(code)
})


# SSH Brute Force Detection
def detect_ssh():
log='/var/log/auth.log'
if not os.path.exists(log): return
hits={}
for l in open(log):
if 'Failed password' in l:
ip=l.split()[-4]
hits[ip]=hits.get(ip,0)+1
for ip,c in hits.items():
if c>=5:
alert('SSH_BRUTE',f'SSH brute force detected ({c} attempts)',ip)


# Insecure Service Exposure
def detect_services():
out=subprocess.getoutput('netstat -tulnp')
for l in out.splitlines():
if any(p in l for p in [':21',':23']):
alert('INSECURE_SERVICE','FTP/Telnet service exposed',l)


# File Integrity Monitoring
def fim():
tgt='config/fim_targets.txt'; db=f'{DATA}/fim_db.json'
state=json.load(open(db)) if os.path.exists(db) else {}
for f in open(tgt):
f=f.strip()
if os.path.exists(f):
h=hashlib.sha256(open(f,'rb').read()).hexdigest()
if f in state and state[f]!=h:
alert('FILE_TAMPERING','Critical file modified',f,'CRITICAL')
state[f]=h
json.dump(state,open(db,'w'),indent=2)


# Save alerts
def save():
json.dump(alerts,open(ALERT_FILE,'w'),indent=2)


if __name__=='__main__':
detect_ssh(); detect_services(); fim(); save()
print('[+] Detection cycle completed')
