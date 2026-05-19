# Windows Active Directory Pentesting Skill

A comprehensive Claude skill covering Windows Active Directory penetration testing from beginner to master level. Built for learners working toward OSCP, CRTO, CRTE, PNPT, and professional red team engagements.

**Scope**: Windows AD only. Azure AD / Entra ID and Linux pivoting are intentionally out of scope — separate skills.

[![Cert Coverage](https://img.shields.io/badge/cert--coverage-interactive-1f6feb?style=flat-square&logo=target&logoColor=white)](./cert-coverage.html)
[![Phases](https://img.shields.io/badge/phases-18-3fb950?style=flat-square)](./README.md#coverage--18-reference-files)
[![Lines](https://img.shields.io/badge/lines-4%2C575-d29922?style=flat-square)](./README.md)
[![Scope](https://img.shields.io/badge/scope-Windows%20AD%20only-f85149?style=flat-square)](./README.md)

---

<!-- CERT COVERAGE BANNER -->
<div id="cert-banner" style="font-family:system-ui,sans-serif;margin:0 0 2rem;">

<p style="font-size:13px;color:#6e7681;margin:0 0 10px;">Click a certification to see topic-by-topic coverage</p>

<div id="cert-cards" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:8px;margin-bottom:14px;"></div>

<div id="cert-detail" style="display:none;border:1px solid #30363d;border-radius:10px;padding:16px;background:#0d1117;"></div>

<style>
.cc{background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:12px;cursor:pointer;transition:border-color .15s}
.cc:hover{border-color:#58a6ff}
.cc.sel{border:2px solid #1f6feb}
.cn{font-size:14px;font-weight:600;color:#e6edf3;margin-bottom:2px}
.co{font-size:11px;color:#8b949e;margin-bottom:8px}
.bw{background:#21262d;border-radius:3px;height:6px;overflow:hidden}
.bf{height:100%;border-radius:3px;transition:width .4s}
.pl{font-size:11px;color:#8b949e;margin-top:4px;text-align:right}
.dh{display:flex;align-items:center;gap:10px;margin-bottom:12px;padding-bottom:10px;border-bottom:1px solid #30363d}
.dt{font-size:15px;font-weight:600;color:#e6edf3}
.ds{font-size:12px;color:#8b949e;margin-top:2px}
.bp{font-size:26px;font-weight:600;margin-left:auto}
.tr{display:flex;align-items:center;gap:8px;font-size:12px;padding:6px 8px;border-radius:6px;background:#161b22;margin-bottom:4px}
.tn{flex:1;color:#c9d1d9}
.tp{font-size:11px;color:#8b949e;min-width:70px}
.b{font-size:10px;padding:2px 7px;border-radius:10px;font-weight:600;white-space:nowrap}
.bf2{background:#1a3d1f;color:#3fb950}
.bp2{background:#3d2e0a;color:#d29922}
.bt{background:#0c2d6b;color:#58a6ff}
.bg{background:#3d0f0f;color:#f85149}
.vd{margin-top:10px;padding:8px 12px;border-radius:6px;background:#161b22;font-size:12px;color:#c9d1d9;border-left:3px solid}
.lg{display:flex;gap:10px;flex-wrap:wrap;margin-top:10px;padding-top:8px;border-top:1px solid #21262d}
.li{display:flex;align-items:center;gap:4px;font-size:11px;color:#8b949e}
</style>

<script>
(function(){
const certs=[
  {id:'oscp',name:'OSCP',org:'OffSec',color:'#f85149',
   focus:'Practical exploitation — AD chain mandatory in exam since 2022',
   verdict:'Excellent. Every topic on the OSCP AD module is covered in depth. The skill goes well beyond OSCP scope.',vc:'#3fb950',
   topics:[
    {n:'AD enumeration (BloodHound, PowerView)',p:'Phase 03',c:'full'},
    {n:'Password spraying + lockout policy check',p:'Phase 02',c:'full'},
    {n:'Kerberoasting + AS-REP Roasting',p:'Phase 04',c:'full'},
    {n:'Pass-the-Hash / Pass-the-Ticket',p:'Phase 05',c:'full'},
    {n:'PsExec, WMI, Evil-WinRM lateral move',p:'Phase 05',c:'full'},
    {n:'ACL abuse (GenericAll, WriteDACL)',p:'Phase 06',c:'full'},
    {n:'DCSync + secretsdump',p:'Phase 07',c:'full'},
    {n:'NTLM relay (Responder + ntlmrelayx)',p:'Phase 04',c:'full'},
    {n:'Report writing — findings + remediation',p:'Phase 12',c:'full'},
    {n:'Evasion basics (AV, AMSI)',p:'Phase 11',c:'partial'},
  ]},
  {id:'pnpt',name:'PNPT',org:'TCM Security',color:'#58a6ff',
   focus:'Heavy AD focus — practical exam on a full AD environment',
   verdict:'Excellent. PNPT is heavily AD-focused and every exam topic is covered. Skill also covers advanced topics well beyond PNPT scope.',vc:'#3fb950',
   topics:[
    {n:'LLMNR/NBT-NS poisoning (Responder)',p:'Phase 02',c:'full'},
    {n:'Password spraying (kerbrute, nxc)',p:'Phase 02',c:'full'},
    {n:'BloodHound + attack path analysis',p:'Phase 03',c:'full'},
    {n:'Kerberoasting + AS-REP Roasting',p:'Phase 04',c:'full'},
    {n:'Token impersonation',p:'Phase 05',c:'partial'},
    {n:'GPP / cpassword (MS14-025)',p:'Phase 04',c:'full'},
    {n:'Golden Ticket + persistence',p:'Phases 07–08',c:'full'},
    {n:'Report writing + executive summary',p:'Phase 12',c:'full'},
    {n:'OSINT + external recon',p:'Phase 01',c:'full'},
  ]},
  {id:'crto',name:'CRTO',org:'Zero-Point Security',color:'#3fb950',
   focus:'Red team ops with Cobalt Strike — C2, evasion, OPSEC discipline',
   verdict:'Very good. Strong on AD attacks. Thin on C2 operation and pivoting — CRTO relies heavily on Cobalt Strike tradecraft which is out of scope here.',vc:'#d29922',
   topics:[
    {n:'Full enumeration chain (LDAP, BloodHound)',p:'Phase 03',c:'full'},
    {n:'Delegation attacks (RBCD, unconstrained)',p:'Phase 06',c:'full'},
    {n:'DPAPI + credential theft',p:'Phase 15',c:'full'},
    {n:'GPO abuse',p:'Phase 06',c:'full'},
    {n:'Forest trust attacks',p:'Phase 09',c:'full'},
    {n:'Persistence (AdminSDHolder, DSRM, etc.)',p:'Phase 08',c:'full'},
    {n:'OPSEC discipline + evasion',p:'Phase 11',c:'partial'},
    {n:'C2 framework operation (Cobalt Strike)',p:'Phase 11',c:'thin'},
    {n:'Pivoting / port forwarding',p:'—',c:'gap'},
  ]},
  {id:'crte',name:'CRTE',org:'Altered Security',color:'#d29922',
   focus:'Pure multi-domain AD attacks — the deepest AD-specific cert',
   verdict:'Excellent for Windows AD topics. The only gap is Azure AD hybrid attacks — CRTE covers on-prem ↔ cloud chains which are explicitly out of this skill\'s scope.',vc:'#3fb950',
   topics:[
    {n:'Full ACL exploitation chain',p:'Phase 06',c:'full'},
    {n:'All three delegation types',p:'Phase 06',c:'full'},
    {n:'Child → parent escalation (SID History)',p:'Phase 09',c:'full'},
    {n:'MSSQL lateral movement',p:'Phase 14',c:'full'},
    {n:'AD CS (ESC1–ESC16)',p:'Phase 10',c:'full'},
    {n:'gMSA + sMSA abuse',p:'Phase 16',c:'full'},
    {n:'Diamond / Sapphire Tickets',p:'Phase 13',c:'full'},
    {n:'ADIDNS / wpad abuse',p:'Phase 16',c:'full'},
    {n:'Advanced Kerberos (noPac, KrbRelay)',p:'Phase 13',c:'full'},
    {n:'Azure AD / Entra ID hybrid attacks',p:'—',c:'gap'},
  ]},
  {id:'ejpt',name:'eJPT',org:'eLearnSecurity',color:'#8b5cf6',
   focus:'Entry-level — basic pentesting including light AD exposure',
   verdict:'More than enough. eJPT barely touches AD. The skill covers everything eJPT needs and vastly more. Only gap is Metasploit-specific modules (out of scope).',vc:'#3fb950',
   topics:[
    {n:'Network discovery + port scanning',p:'Phase 03',c:'full'},
    {n:'SMB enumeration + null sessions',p:'Phase 03',c:'full'},
    {n:'Basic credential attacks',p:'Phase 04',c:'full'},
    {n:'Simple lateral movement (PsExec)',p:'Phase 05',c:'full'},
    {n:'Basic report writing',p:'Phase 12',c:'full'},
    {n:'Metasploit usage',p:'—',c:'gap'},
  ]},
  {id:'osep',name:'OSEP',org:'OffSec',color:'#f0883e',
   focus:'Advanced evasion, process injection, C2 development, AD at scale',
   verdict:'Good for the AD portions. OSEP is an advanced evasion cert — it goes deeper on shellcode, loader dev, and C2 internals than this skill covers. Use as AD supplement.',vc:'#d29922',
   topics:[
    {n:'Process injection primitives',p:'Phase 11',c:'partial'},
    {n:'AMSI/ETW bypass depth',p:'Phase 11',c:'partial'},
    {n:'Custom C2 / shellcode loaders',p:'Phase 11',c:'thin'},
    {n:'AD at scale (large env techniques)',p:'Phases 03–09',c:'full'},
    {n:'SCCM + WSUS attacks',p:'Phase 17',c:'full'},
    {n:'Phishing + initial access tradecraft',p:'Phase 02',c:'partial'},
    {n:'Linux + macOS pivoting',p:'—',c:'gap'},
    {n:'Antivirus bypass development',p:'Phase 11',c:'thin'},
  ]},
];

const W={full:1,partial:.6,thin:.3,gap:0};
function pct(t){return Math.round(t.reduce((s,x)=>s+W[x.c],0)/t.length*100)}
function barCol(p){return p>=85?'#3fb950':p>=65?'#d29922':'#f85149'}
function bClass(c){return{full:'bf2',partial:'bp2',thin:'bt',gap:'bg'}[c]}
function bLabel(c){return{full:'Covered',partial:'Partial',thin:'Thin',gap:'Gap'}[c]}

let sel=null;

function renderCards(){
  document.getElementById('cert-cards').innerHTML=certs.map(c=>{
    const p=pct(c.topics);
    return `<div class="cc${sel===c.id?' sel':''}" onclick="selCert('${c.id}')">
      <div class="cn">${c.name}</div>
      <div class="co">${c.org}</div>
      <div class="bw"><div class="bf" style="width:${p}%;background:${barCol(p)}"></div></div>
      <div class="pl">${p}% covered</div>
    </div>`;
  }).join('');
}

window.selCert=function(id){
  sel=id; renderCards();
  const c=certs.find(x=>x.id===id);
  const p=pct(c.topics);
  const d=document.getElementById('cert-detail');
  d.style.display='block';
  d.innerHTML=`
    <div class="dh">
      <div><div class="dt">${c.name} — ${c.org}</div><div class="ds">${c.focus}</div></div>
      <div class="bp" style="color:${barCol(p)}">${p}%</div>
    </div>
    ${c.topics.map(t=>`
      <div class="tr">
        <div class="tn">${t.n}</div>
        <div class="tp">${t.p}</div>
        <span class="b ${bClass(t.c)}">${bLabel(t.c)}</span>
      </div>`).join('')}
    <div class="lg">
      <div class="li"><span class="b bf2">Covered</span> Full depth</div>
      <div class="li"><span class="b bp2">Partial</span> Lighter than cert needs</div>
      <div class="li"><span class="b bt">Thin</span> Concepts only</div>
      <div class="li"><span class="b bg">Gap</span> Not in scope</div>
    </div>
    <div class="vd" style="border-color:${c.vc}">${c.verdict}</div>`;
};

renderCards();
selCert('crte');
})();
</script>
</div>
<!-- END BANNER -->

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
