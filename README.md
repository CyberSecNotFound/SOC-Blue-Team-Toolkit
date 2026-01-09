# 🛡️ SOC Blue Team Toolkit

**Detection → Alerting → Threat Hunting → Analysis**

---
## 🧠 Fitur Utama

### 🔍 Detection (SOC Level 1)

* SSH brute force detection (`/var/log/auth.log`)
* Insecure service exposure (FTP / Telnet)
* File Integrity Monitoring (FIM)

### 🧠 Threat Hunting (SOC Level 2)

* IOC correlation
* Repeated attacker detection
* Alert history analysis

### 🧭 MITRE ATT&CK Mapping

* T1110 – Brute Force
* T1078 – Valid Accounts
* T1562 – Impair Defenses

---

## 🧱 Arsitektur

```
[Kali Linux]
 ├── Log Sources
 ├── SOC Detection Engine (soc.py)
 ├── Alert Database (JSON)
 └── Threat Hunting Engine (hunter.py)
```
---

---

## ⚙️ Instalasi (Kali Linux)

```bash
sudo apt update
sudo apt install -y python3 python3-pip net-tools openssh-server
pip3 install -r requirements.txt
```

---

## 🚀 Cara Menjalankan

### 1️⃣ Jalankan Detection (SOC L1)

```bash
sudo python3 soc.py
```

Output normal:

```
[+] SOC detection cycle completed
```

> Tidak ada alert = **kondisi normal sistem aman**

---

### 2️⃣ Jalankan Threat Hunting (SOC L2)

```bash
python3 hunter.py
```

Output hanya muncul jika IOC **berulang**.

---

## 🧪 Simulasi Incident (REAL)

### 🔥 SSH Brute Force

```bash
sudo hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://127.0.0.1
sudo python3 soc.py
```

### 🔥 File Tampering

```bash
sudo nano /etc/passwd
sudo python3 soc.py
```

---

## 📊 Cek Alert

```bash
cat data/alerts.json | jq .
```

---

## 🎤 Penjelasan untuk Interview

> "Saya membangun SOC Blue Team tool berbasis Kali Linux CLI dengan log detection, file integrity monitoring, MITRE ATT&CK mapping, dan threat hunting IOC. Tool ini event-driven dan tidak menghasilkan false positive."

---

## 🏆 Target Role

* SOC Analyst Level 1
* SOC Analyst Level 2 (Junior)
* Blue Team Intern / Junior

---

## ⚠️ Disclaimer

Tool ini dibuat **hanya untuk pembelajaran dan lab pribadi**.
Jangan gunakan untuk menyerang sistem tanpa izin.

---

## 👤 Author

**Stay safe. Think before you click.**
