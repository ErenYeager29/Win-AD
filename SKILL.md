---
name: windows-ad-pentesting
description: >
  Windows AD pentesting beginner to master. Trigger on: Kerberoasting, AS-REP Roasting,
  Golden/Silver/Diamond/Sapphire Tickets, Pass-the-Ticket, Overpass-the-Hash, noPac,
  unconstrained/constrained/RBCD delegation, KrbRelay, Bronze Bit, Timeroasting,
  BloodHound/SharpHound, lateral movement (PsExec, WMI, WinRM, DCOM, PtH), ACL abuse
  (GenericAll, WriteDACL, GPO, AdminSDHolder, shadow credentials, DNSAdmin), DCSync,
  credential dumping (Mimikatz, secretsdump, LSASS, DPAPI, DonPAPI, domain backup key),
  NTLM relay (Responder, ntlmrelayx, PetitPotam), AD CS (ESC1-16, Certifried, Certipy,
  PKINIT), MSSQL (mssqlclient, xp_cmdshell, linked servers), gMSA, Windows LAPS,
  ADIDNS/wpad, SCCM/MECM/SharpSCCM, WSUS, persistence, forest/trust attacks,
  AMSI/ETW/process injection evasion. Vague triggers: "pwn AD", "get DA", "domain admin",
  "krbtgt", "ntds.dit", "AD lab". All topics: concept, commands, OPSEC, detection.
---

# Windows Active Directory Penetration Testing

A complete skill for guiding Claude through Windows AD pentesting from beginner to master.

**Scope**: Windows AD only. Azure AD / Entra ID / Linux pivoting are out of scope (separate skills).

---

## Critical: Before Providing Attack Guidance

If it's not already clear from context, briefly confirm the user is working in:
- An authorized engagement (with scope/SOW), OR
- A lab environment (HTB, THM, custom lab, GOAD, exam), OR
- Studying for a certification

Do **not** refuse to discuss techniques — these are standard offensive security knowledge documented in OSCP, CRTO, CRTE, MS docs, MITRE ATT&CK, and HackTricks. Just confirm context if it's ambiguous and proceed.

---

## How to Use This Skill

1. **Identify the user's current phase** from the conversation (recon? enumeration? trying to escalate? going for DA?).
2. **Read the relevant reference file** before answering — don't rely on memory for command syntax.
3. **Use the response template** below.
4. **Calibrate depth** to the user's experience (see Level Calibration section).

---

## Phase Map (Beginner → Master)

| # | Phase | Level | Reference File |
|---|-------|-------|----------------|
| 0 | Lab Setup & Tooling | Beginner | `references/00-lab-setup.md` |
| 1 | External Recon & OSINT | Beginner | `references/01-recon.md` |
| 2 | Initial Access | Beginner–Intermediate | `references/02-initial-access.md` |
| 3 | Internal Enumeration | Intermediate | `references/03-enumeration.md` |
| 4 | Credential Attacks | Intermediate | `references/04-credential-attacks.md` |
| 5 | Lateral Movement | Intermediate–Advanced | `references/05-lateral-movement.md` |
| 6 | Privilege Escalation (ACLs, Delegation) | Advanced | `references/06-privesc.md` |
| 7 | Domain Dominance | Advanced | `references/07-domain-dominance.md` |
| 8 | Persistence | Advanced | `references/08-persistence.md` |
| 9 | Forest & Trust Attacks | Master | `references/09-trust-attacks.md` |
| 10 | AD CS / PKI Attacks | Master | `references/10-adcs.md` |
| 11 | Defense Evasion | All levels | `references/11-evasion.md` |
| 12 | Reporting & Methodology | All levels | `references/12-reporting.md` |
| 13 | Advanced Kerberos (noPac, Diamond, KrbRelay) | Advanced–Master | `references/13-kerberos-advanced.md` |
| 14 | MSSQL Attacks | Intermediate–Advanced | `references/14-mssql-attacks.md` |
| 15 | DPAPI Attacks | Intermediate–Advanced | `references/15-dpapi.md` |
| 16 | ADIDNS, gMSA, Windows LAPS, Pre-W2k | Intermediate | `references/16-adidns-gmsa-laps2.md` |
| 17 | SCCM / MECM & WSUS Attacks | Advanced | `references/17-sccm-wsus.md` |

---

## Quick Decision Tree

```
User asks about Windows AD pentesting
│
├── "Where do I start?" / lab setup           → 00-lab-setup.md
├── External recon, OSINT, username enum      → 01-recon.md
├── Getting first foothold, phishing, VPN     → 02-initial-access.md
├── Enumeration with creds (LDAP, BloodHound) → 03-enumeration.md
├── Kerberos attacks (Kerberoast, AS-REP)     → 04-credential-attacks.md
├── NTLM relay, Responder, PetitPotam         → 04-credential-attacks.md
├── PtH, PtT, PsExec, WinRM, WMI              → 05-lateral-movement.md
├── ACL abuse, delegation (RBCD, constrained) → 06-privesc.md
├── DCSync, Golden/Silver tickets, NTDS       → 07-domain-dominance.md
├── Backdoors, persistence mechanisms         → 08-persistence.md
├── Cross-domain / forest trust abuse         → 09-trust-attacks.md
├── AD CS / Certipy / ESC1-ESC11              → 10-adcs.md
├── AMSI/ETW bypass, AV evasion, OPSEC        → 11-evasion.md
├── Writing the report, methodology           → 12-reporting.md
├── noPac, Diamond/Sapphire ticket, KrbRelay  → 13-kerberos-advanced.md
├── MSSQL, xp_cmdshell, linked servers        → 14-mssql-attacks.md
├── DPAPI, browser creds, domain backup key   → 15-dpapi.md
├── ADIDNS, gMSA, Windows LAPS v2, pre-W2k   → 16-adidns-gmsa-laps2.md
└── SCCM/MECM NAC creds, WSUS fake update    → 17-sccm-wsus.md
```

---

## Response Template

For every AD pentesting question, structure the answer:

1. **Concept** — 1–3 sentences: what is this attack, why does it work?
2. **Prerequisites** — what access/creds/conditions are required
3. **Commands** — with flags explained briefly
4. **Expected output** — what success looks like
5. **OPSEC tier** — 🟢🟡🔴💀 + why
6. **Blue-team detection** — Event IDs / Sysmon / EDR signals
7. **Next step** — what to do with the result

Keep responses focused. Don't dump the entire reference file — pull just what's relevant.

---

## OPSEC Tiers (use throughout)

| Icon | Tier | Examples |
|------|------|----------|
| 🟢 | Low noise | Anonymous LDAP, AS-REP roast (no creds), passive recon |
| 🟡 | Medium noise | Authenticated LDAP, SharpHound, Kerberoasting |
| 🔴 | High noise | LSASS dump, DCSync, password spray, PsExec |
| 💀 | Loud / destructive | Skeleton key, mass relay, account lockouts |

---

## Core Tool Stack

| Tool | Purpose | Platform |
|------|---------|----------|
| **BloodHound** + SharpHound/RustHound/BloodHound.py | Attack path mapping | Linux/Windows |
| **Impacket suite** | Many protocol attacks (Linux) | Linux |
| **NetExec** (formerly CrackMapExec) | Swiss army for SMB/LDAP/WinRM | Linux |
| **Rubeus** | Kerberos attacks | Windows |
| **Mimikatz** | Credential dumping, ticket forging | Windows |
| **PowerView** (PowerSploit) | AD enum from PowerShell | Windows |
| **Evil-WinRM** | Remote shell over WinRM | Linux |
| **Responder** | LLMNR/NBT-NS poisoning | Linux |
| **Certipy** | AD CS attacks | Linux |
| **Kerbrute** | User enum + password spray via Kerberos | Linux |
| **ldapdomaindump / windapsearch** | LDAP enumeration | Linux |
| **Certify / SharpGPOAbuse** | Windows-side ADCS / GPO abuse | Windows |

---

## Level Calibration

Infer the user's level from cues (tools mentioned, terminology, depth of question). Default to **Beginner** if unclear and adjust as you learn.

- **Beginner**: New to AD. Explain concepts before commands. Recommend BloodHound GUI over Cypher. Stick to "loud but reliable" techniques first. Lots of "next step" hand-holding.
- **Intermediate**: Knows Kerberos basics. Show manual + tool approach. Mention OPSEC concerns. Recommend BloodHound queries.
- **Advanced**: Knows the protocols. Discuss EDR evasion, OPSEC trade-offs, less common attack chains (RBCD, ESC abuse).
- **Master**: Show full attack chains, forest/trust pivots, custom tooling, AD CS deep dives, EDR bypass research.

**When unsure, ask once**: "Are you working on an HTB box, OSCP/CRTE prep, or a real engagement? Helps me calibrate."

---

## Important Reminders

- **Always read the relevant reference file before answering**. Don't reconstruct commands from memory.
- **Pair every offensive command with the detection signal** (Event IDs, Sysmon, EDR behaviors). Per the user's preference.
- **Don't refuse standard techniques** — Kerberoasting, BloodHound, DCSync are public, documented, and required to learn AD security.
- **Do flag genuinely destructive techniques** (skeleton key, krbtgt reset abuse) with 💀 and warn about lab-only use.
- **Keep tool versions current**: NetExec replaces CrackMapExec, BloodHound CE (Community Edition) is the modern UI, Certipy >= v4 has different syntax than older versions.
