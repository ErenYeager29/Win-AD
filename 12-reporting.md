# Phase 12: Reporting & Methodology

> The deliverable matters more than the technical work. A clear, actionable report is what the customer pays for.

---

## Standard AD Pentest Report Sections

1. **Executive Summary** — 1 page, for executives. No tools, no jargon.
2. **Methodology** — what frameworks (PTES, OWASP, MITRE ATT&CK) and approach.
3. **Scope & Rules of Engagement** — what was in/out of scope, timestamps, accounts used.
4. **Attack Narrative** — the story: how you went from outside to DA, step by step.
5. **Findings** — individual vulnerabilities, each with: severity, description, evidence, remediation.
6. **Strategic Recommendations** — long-term hardening: tiered admin, Defender for Identity, LAPS, etc.
7. **Appendices** — full hash dumps, tool output, screenshots, tester logbook.

---

## Severity Rubric (CVSS-ish, AD-flavored)

| Severity | AD Examples |
|----------|------------|
| Critical | Path to DA in <1 day from no creds; full domain compromise; krbtgt exposure |
| High | Path to DA from a domain user account; DCSync rights misassigned; AD CS ESC1/8 |
| Medium | Kerberoastable account with weak password; AS-REP roastable; misconfigured ACLs that need multiple hops |
| Low | LLMNR enabled but no relayable targets; password policy below recommended |
| Info | Verbose error messages; outdated PowerShell logging |

---

## The Attack Narrative — Recommended Structure

Write this like a thriller, not a tool dump:

> **Day 1, 09:14 UTC** — Starting from an external position with no credentials, we identified the company's primary domain (`corp.target.com`) and its mail infrastructure via passive DNS reconnaissance...
>
> **Day 1, 11:48 UTC** — Using employee names harvested from LinkedIn, we built a username list of 612 candidates. A Kerberos pre-authentication enumeration via `kerbrute` confirmed 348 of these were valid AD accounts (see Appendix A)...
>
> **Day 1, 14:22 UTC** — A password spray of `Winter2024!` against the validated list returned three valid sets of credentials. One of these, `j.thompson`, was a member of the IT support team...
>
> **Day 1, 16:10 UTC** — From j.thompson's account, BloodHound revealed a path to Domain Admin via an unconstrained delegation server (`PRINTSRV01.corp.target.com`) and a service account (`svc_sql`) with a Kerberoastable SPN. The svc_sql account password was `SQLAdmin2023!` and granted local admin rights on the print server...

Include the **exact timestamps and commands** for the customer's SOC to replay against their logs. This is one of the most valuable parts of the report — it lets blue team validate their detections worked (or didn't).

---

## Findings Template

```markdown
### F-001: Kerberoastable Service Account with Weak Password

**Severity**: High
**CVSS 3.1**: 8.1 (AV:N / AC:L / PR:L / UI:N / S:U / C:H / I:H / A:H)
**Affected**: `CORP\svc_sql`

**Description**
The domain service account `svc_sql` has a Service Principal Name (SPN) of
`MSSQLSvc/db01.corp.target.com:1433`, allowing any authenticated domain user to
request a Kerberos service ticket for it. The encrypted ticket contains a hash
derived from the account's password. We extracted this ticket and recovered the
password (`SQLAdmin2023!`) offline in under 4 minutes using common cracking tools.

The svc_sql account is a member of `BUILTIN\Administrators` on three production
database servers, providing immediate lateral movement.

**Evidence**
- Output of `GetUserSPNs.py` showing the ticket request (Appendix B-2)
- Hashcat session log showing recovery time (Appendix B-3)

**Recommendation**
1. (Immediate) Reset the svc_sql password to a 25+ character random string.
2. (Short term) Migrate svc_sql to a Group Managed Service Account (gMSA),
   which automatically rotates passwords every 30 days with crypto-quality
   randomness — making Kerberoasting infeasible.
3. (Strategic) Audit all SPN-bearing accounts for password complexity.
   Implement a SOC detection rule for Event 4769 with `Ticket Encryption Type
   = 0x17 (RC4-HMAC)` as this is a strong Kerberoasting indicator on modern
   AES-default domains.
```

---

## Common Findings Checklist (use as your "did I check?" list)

- [ ] Password policy: min length, history, lockout, age, complexity
- [ ] Kerberoastable accounts with crackable passwords
- [ ] AS-REP roastable accounts
- [ ] GPP cpassword in SYSVOL
- [ ] LLMNR/NBT-NS enabled
- [ ] SMB signing not required on member servers/workstations
- [ ] LAPS not deployed (or partially deployed)
- [ ] AdminSDHolder ACL contains non-default entries
- [ ] Domain object ACL contains non-default DCSync grants
- [ ] Unconstrained delegation on non-DC hosts
- [ ] Constrained delegation with protocol transition (`TrustedToAuthForDelegation`)
- [ ] `ms-DS-MachineAccountQuota` > 0 for unprivileged users
- [ ] Anonymous LDAP / null SMB allowed
- [ ] AD CS templates with `Enrollee Supplies Subject` (ESC1)
- [ ] AD CS CA with `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6)
- [ ] AD CS web enrollment exposed without EPA (ESC8)
- [ ] Sensitive accounts not in `Protected Users` group
- [ ] Stale accounts (no logon in 90 days) — not directly an attack but bloat
- [ ] Service accounts with `Password never expires`
- [ ] Tier-0 admins logging into Tier-1/2 workstations (credential exposure)
- [ ] Print Spooler running on DC (PrinterBug)
- [ ] EFSRPC unauthenticated coercion (PetitPotam patch level)

---

## Strategic Recommendations Template

Beyond per-finding fixes, every AD pentest report should recommend:

1. **Tiered Administration Model** — separate Tier-0 (forest-critical), Tier-1 (server), Tier-2 (workstation) accounts. No DA accounts logging into workstations.
2. **Microsoft Defender for Identity** (formerly ATA/Azure ATP) — the most cost-effective AD detection investment.
3. **LAPS / Windows LAPS** — randomized local admin passwords per host.
4. **gMSA** (Group Managed Service Accounts) — replace static service-account passwords.
5. **Protected Users group + Authentication Policies** — modern Kerberos hardening; blocks NTLM, restricts ticket lifetime, blocks delegation.
6. **Disable LLMNR + NBT-NS** via GPO.
7. **Require SMB signing** on all hosts.
8. **AD CS hardening**: remove `EDITF_ATTRIBUTESUBJECTALTNAME2`, require manager approval on sensitive templates, deploy `StrongCertificateBindingEnforcement = 2`.
9. **Privileged Access Workstations (PAWs)** — admins log in from dedicated, locked-down workstations only.
10. **AD Recycle Bin + regular backups** — for the day the bad guys delete things.

---

## Methodology Frameworks to Cite

- **PTES** (Penetration Testing Execution Standard) — `http://www.pentest-standard.org`
- **OWASP** for any web parts
- **MITRE ATT&CK** — map each finding to ATT&CK techniques (great for SOC alignment)
- **NIST SP 800-115** — technical guide to information security testing

Mapping findings to MITRE ATT&CK in the report helps the customer's blue team. Examples:
- Kerberoasting → `T1558.003`
- Pass-the-Hash → `T1550.002`
- DCSync → `T1003.006`
- Golden Ticket → `T1558.001`
- Pass-the-Ticket → `T1550.003`

---

## What NOT to do

- ❌ Don't list every command you ran. Customers don't want a tool transcript.
- ❌ Don't recommend "use a stronger password" without specifics (length, complexity, source: NIST 800-63B).
- ❌ Don't include screenshots of cracked passwords in plaintext (use hashes or redaction).
- ❌ Don't pad with generic security advice. Every recommendation should map to a specific finding.
- ❌ Don't say "we found 50 issues" if 45 of them are noise. Prioritize ruthlessly.

---

## Post-Engagement Cleanup

Before delivering the report, confirm with the customer that:
- All accounts you created are documented and disabled/deleted
- All ACL grants you made (especially DCSync, AdminSDHolder) are reverted
- All forged tickets are documented with a krbtgt-reset recommendation
- All shadow credentials, GPO modifications, and persistence mechanisms are listed
- All test files dropped to shares are deleted

Hand the customer a separate "remediation evidence" appendix where they can verify each item.

---

## Quick Wins to Highlight

Customers love these because they're cheap and high-impact:

1. Reset krbtgt password (twice, 24 hours apart) → kills any golden tickets
2. Enable LSA Protection (RunAsPPL=1 in registry) → much harder LSASS dump
3. Disable LLMNR via GPO → kills the easiest LAN attack
4. Require SMB signing on all hosts → kills NTLM relay
5. Move Tier-0 admins to Protected Users group → blocks NTLM, restricts cached credentials
6. Audit and revoke `Account Operators`, `Backup Operators`, `Server Operators` — these often have unexpected privileges
7. Disable WPAD via GPO

---

That's the end of the skill content. Now go practice in a lab.
