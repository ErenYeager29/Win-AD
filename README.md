# Windows Active Directory Pentesting Skill

A comprehensive Claude skill covering Windows Active Directory penetration testing from beginner to master level. Built for learners working toward OSCP, CRTO, CRTE, PNPT, and professional red team engagements.

**Scope**: Windows AD only. Azure AD / Entra ID and Linux pivoting are intentionally out of scope — separate skills.

[![Cert Coverage](https://img.shields.io/badge/cert--coverage-interactive-1f6feb?style=flat-square&logo=target&logoColor=white)](./cert-coverage.html)
[![Phases](https://img.shields.io/badge/phases-18-3fb950?style=flat-square)](./README.md#coverage--18-reference-files)
[![Lines](https://img.shields.io/badge/lines-4%2C575-d29922?style=flat-square)](./README.md)
[![Scope](https://img.shields.io/badge/scope-Windows%20AD%20only-f85149?style=flat-square)](./README.md)

---

## Certification Coverage

> **Interactive version** — open [`cert-coverage.html`](./cert-coverage.html) in a browser for clickable cert cards with topic-by-topic breakdown.

| Cert | Org | Coverage | Best for |
|------|-----|:--------:|---------|
| **CRTE** | Altered Security | 🟢 90% | Best match — pure Windows AD, every phase covered |
| **OSCP** | OffSec | 🟢 96% | Excellent — full AD module + goes well beyond exam scope |
| **PNPT** | TCM Security | 🟢 96% | Excellent — AD-heavy practical exam, every topic covered |
| **CRTO** | Zero-Point Security | 🟡 77% | Good — AD attacks covered; C2 tradecraft and pivoting are out of scope |
| **eJPT** | eLearnSecurity | 🟢 83% | More than enough — skill far exceeds eJPT AD requirements |
| **OSEP** | OffSec | 🔴 55% | Partial — good for AD portions; use as supplement for evasion/loader dev depth |

**Coverage key**: 🟢 85%+ full depth · 🟡 65–84% good with some gaps · 🔴 <65% use as supplement


---

## What This Skill Does

When loaded, this skill guides Claude to answer AD pentesting questions with:

- **Hybrid format**: brief concept explanation → prerequisites → commands → expected output → OPSEC tier → blue-team detection → next step
- **OPSEC tiers** on every technique: 🟢 Low / 🟡 Medium / 🔴 High / 💀 Destructive
- **Blue-team detection signals** for every offensive technique — Event IDs, Sysmon events, Defender for Identity alert names
- **Level calibration**: beginner gets concept-first hand-holding; advanced users get raw technique depth
- **Current tooling**: NetExec (not CrackMapExec), BloodHound CE, Certipy v4+, modern Impacket syntax

---

## Coverage — 18 Reference Files

| # | Phase | Level | Topics |
|---|-------|-------|--------|
| 00 | Lab Setup & Tooling | Beginner | GOAD, manual DC build, Kali toolchain, BloodHound CE, cert roadmap |
| 01 | External Recon & OSINT | Beginner | Subdomain enum, email harvesting, username generation, kerbrute userenum |
| 02 | Initial Access | Beginner–Int | Password spray, LLMNR/NBT-NS, RDP/Citrix, device code phishing, MFA fatigue, Evilginx2 |
| 03 | Internal Enumeration | Intermediate | LDAP, PowerView, BloodHound + Cypher query library, SMB, ACL rights, RODC |
| 04 | Credential Attacks | Intermediate | Kerberoasting, AS-REP, NTLM relay + coercion chain, GPP cpassword, LAPS, hash cracking modes |
| 05 | Lateral Movement | Int–Advanced | PtH, PtT, Overpass-the-Hash, PsExec/SMBExec/WinRM/WMI/DCOM, hunting DA |
| 06 | Privilege Escalation | Advanced | ACL abuse (GenericAll→DCSync), shadow credentials, unconstrained/constrained/RBCD delegation, GPO, AdminSDHolder, DNSAdmin, Schema Admin |
| 07 | Domain Dominance | Advanced | LSASS dumping methods, DCSync, NTDS.dit, Golden Ticket, Silver Ticket, Skeleton Key |
| 08 | Persistence | Advanced | Golden/Silver, DCSync ACL grant, AdminSDHolder, DSRM backdoor, SID History, WMI subscriptions, cleanup checklist |
| 09 | Forest & Trust Attacks | Master | Trust types, SID filtering, child→parent via SID History golden ticket, trust key forging |
| 10 | AD CS / PKI Attacks | Master | ESC1–ESC16, Certifried, Certipy, PKINIT auth, LDAP signing/EPA, defense mitigations |
| 11 | Defense Evasion | All | AMSI bypass, ETW patching, AV evasion, sleep obfuscation, process injection, userland unhooking, LSASS stealth |
| 12 | Reporting | All | Report structure, severity rubric, attack narrative template, findings template, MITRE ATT&CK mappings, quick wins |
| 13 | Advanced Kerberos | Advanced–Master | noPac/sAMAccountName spoofing, Diamond Ticket, Sapphire Ticket, Bronze Bit, KrbRelay/KrbRelayUp, Timeroasting |
| 14 | MSSQL Attacks | Int–Advanced | Discovery, mssqlclient, xp_cmdshell, impersonation chains, linked server hopping, UNC coercion |
| 15 | DPAPI | Int–Advanced | Domain backup key, masterkey decryption, Chrome/Edge creds, Credential Manager, DonPAPI, AAD Connect MSOL extraction |
| 16 | ADIDNS, gMSA, LAPS v2, Pre-W2k | Intermediate | Rogue DNS records, gMSA password reading, Windows LAPS new schema, pre-Windows-2000 computer accounts |
| 17 | SCCM / MECM & WSUS | Advanced | NAC credential extraction, SCCM site takeover, SharpSCCM, WSUS PyWSUS MITM, SharpWSUS |

---

## Techniques Covered

<details>
<summary><strong>Kerberos Attacks</strong></summary>

- Kerberoasting (RC4 + AES, targeted)
- AS-REP Roasting
- Pass-the-Ticket (PtT)
- Overpass-the-Hash
- Golden Ticket (Mimikatz, ticketer.py, Rubeus)
- Silver Ticket
- Diamond Ticket
- Sapphire Ticket
- noPac / sAMAccountName spoofing (CVE-2021-42278/42287)
- Bronze Bit (CVE-2020-17049)
- KrbRelay / KrbRelayUp (local privesc)
- Timeroasting
- Skeleton Key

</details>

<details>
<summary><strong>Credential Attacks</strong></summary>

- NTLM relay (Responder + ntlmrelayx)
- Coercion: PetitPotam, PrinterBug, DFSCoerce, Coercer, ShadowCoerce
- GPP cpassword (MS14-025)
- LAPS reading (legacy + Windows LAPS v2)
- gMSA password reading (gMSADumper, nxc)
- DPAPI (domain backup key, browser creds, AAD Connect)
- MSSQL credential extraction
- SCCM Network Access Account (NAC)
- Pass-the-Hash

</details>

<details>
<summary><strong>Enumeration</strong></summary>

- BloodHound CE + SharpHound / RustHound / bloodhound-python
- 15 practical BloodHound Cypher queries
- PowerView full command reference
- ldapdomaindump, windapsearch
- NetExec (SMB/LDAP/WinRM/MSSQL)
- ACL enumeration (dacledit, PowerView)
- ADIDNS enumeration and abuse
- RODC enumeration and partial NTDS extraction

</details>

<details>
<summary><strong>Privilege Escalation</strong></summary>

- ACL primitives: GenericAll, GenericWrite, WriteDACL, WriteOwner, AllExtendedRights
- Targeted Kerberoasting
- Shadow Credentials (Certipy, Whisker)
- Unconstrained Delegation + coercion
- Constrained Delegation (S4U2Self/S4U2Proxy)
- RBCD (full 4-step chain)
- GPO abuse (SharpGPOAbuse, pyGPOAbuse)
- AdminSDHolder
- DNSAdmin DLL load
- Schema Admin abuse

</details>

<details>
<summary><strong>AD CS / PKI</strong></summary>

- ESC1–ESC8 (full attack commands)
- ESC9, ESC10, ESC11, ESC13, ESC14, ESC15, ESC16
- Certifried (CVE-2022-26923)
- LDAP signing / channel binding explanation
- ESC4 template modification + restore
- ESC8 full relay chain (PetitPotam → ntlmrelayx → cert → DCSync)
- PKINIT auth (certipy auth)

</details>

<details>
<summary><strong>Lateral Movement & Execution</strong></summary>

- PsExec, SMBExec, WMIexec, atexec, DCOM
- Evil-WinRM (password, hash, Kerberos)
- MSSQL (xp_cmdshell, linked server hopping, UNC coercion)
- SCCM script deployment to all managed clients
- WSUS fake update injection

</details>

<details>
<summary><strong>Persistence</strong></summary>

- Golden / Silver Ticket
- DCSync ACL grant
- AdminSDHolder backdoor
- DSRM backdoor
- Shadow Credentials (persistent)
- SID History injection
- WMI event subscriptions
- DCShadow
- Cleanup checklist

</details>

<details>
<summary><strong>Trust & Forest Attacks</strong></summary>

- Trust types and SID filtering explained
- Child → parent escalation via SID History golden ticket
- Inter-realm trust key forging
- Foreign group membership enumeration

</details>

<details>
<summary><strong>Evasion</strong></summary>

- AMSI bypass (concepts + AmsiTrigger workflow)
- ETW patching
- AV evasion (Donut, ThreatCheck, DefenderCheck)
- Sleep obfuscation (Ekko, Foliage)
- Process injection primitives (Early Cascade, Mockingjay, thread hijacking)
- Userland unhooking (Hell's Gate, indirect syscalls, fresh NTDLL map)
- LSASS stealth (nanodump, PPLBlade, task manager)

</details>

---

## File Structure

```
windows-ad-pentesting/
├── SKILL.md                          # Router: phase map, decision tree, response template
├── README.md                         # This file
├── evals/
│   └── evals.json                    # 10 test prompts for skill validation
└── references/
    ├── 00-lab-setup.md
    ├── 01-recon.md
    ├── 02-initial-access.md
    ├── 03-enumeration.md
    ├── 04-credential-attacks.md
    ├── 05-lateral-movement.md
    ├── 06-privesc.md
    ├── 07-domain-dominance.md
    ├── 08-persistence.md
    ├── 09-trust-attacks.md
    ├── 10-adcs.md
    ├── 11-evasion.md
    ├── 12-reporting.md
    ├── 13-kerberos-advanced.md
    ├── 14-mssql-attacks.md
    ├── 15-dpapi.md
    ├── 16-adidns-gmsa-laps2.md
    └── 17-sccm-wsus.md
```

---

## How Responses Are Structured

Every answer follows this template:

```
Concept       — what is this attack, why does it work (2–3 sentences)
Prerequisites — what access / conditions are required
Commands      — with flags briefly explained
Expected output — what success looks like
OPSEC tier    — 🟢 / 🟡 / 🔴 / 💀 with reason
Detection     — Event IDs, Sysmon events, EDR/DfI alert names
Next step     — what to do with the result
```

---

## Intended Audience

- **HTB / TryHackMe** — AD boxes and Pro Labs (Forest, Active, Offshore, Zephyr)
- **Certification prep** — OSCP (AD chain), PNPT, CRTO, CRTE, CRTM, OSEP
- **Professional pentests** — real engagements with scope/SOW
- **Blue team / defenders** — every technique includes what to look for

---

## What's Not Covered

- Azure AD / Entra ID attacks (separate skill)
- Linux / macOS privilege escalation (separate skill)
- Web application attacks (separate skill)
- Physical access / social engineering depth (brief phishing overview only)
- Full C2 framework setup and operation

---

## Key Tools Referenced

| Tool | Purpose |
|------|---------|
| BloodHound CE + SharpHound | Attack path mapping |
| Impacket suite | GetUserSPNs, secretsdump, getST, ticketer, mssqlclient, etc. |
| NetExec (nxc) | SMB/LDAP/WinRM/MSSQL Swiss army |
| Rubeus | Kerberos attacks (Windows) |
| Mimikatz | Credential dumping, ticket forging |
| PowerView | AD enumeration from PowerShell |
| Evil-WinRM | WinRM shell (Linux) |
| Responder + ntlmrelayx | NTLM relay chain |
| Certipy | AD CS attacks |
| Kerbrute | Username enum + password spray |
| SharpSCCM / sccmhunter | SCCM/MECM attacks |
| DonPAPI | Remote DPAPI credential extraction |
| gMSADumper | gMSA password reading |
| dnstool.py | ADIDNS record injection |
| SharpWSUS / PyWSUS | WSUS fake update delivery |
| nanodump | Stealthy LSASS dumping |

---

## Peer Review

This skill was reviewed against the "beginner to master" scope after initial release. The following gaps from that review were addressed in v2:

- **Added**: noPac, Diamond/Sapphire Ticket, Bronze Bit, KrbRelay, Timeroasting (Phase 13)
- **Added**: MSSQL full attack chain (Phase 14)
- **Added**: DPAPI including domain backup key and AAD Connect (Phase 15)
- **Added**: ADIDNS, gMSA, Windows LAPS v2, pre-W2k accounts (Phase 16)
- **Added**: SCCM/MECM and WSUS attacks (Phase 17)
- **Added**: ESC5, ESC13–16, Certifried, LDAP signing/EPA explanation (Phase 10)
- **Added**: Process injection, sleep obfuscation, userland unhooking, AMSI technical depth (Phase 11)
- **Added**: 15 BloodHound Cypher queries, RODC section (Phase 03)
- **Added**: DNSAdmin, Schema Admin abuse (Phase 06)
- **Added**: Device code phishing, MFA fatigue, consent phishing, Evilginx2 (Phase 02)
- **Added**: Skeleton Key full technical detail and cleanup (Phase 08)
