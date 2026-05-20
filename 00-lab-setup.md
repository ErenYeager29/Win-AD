# Phase 0: Lab Setup & Tooling

> Before attacking anything, you need a safe environment to practice. This phase covers building one.

---

## Recommended Path for Beginners

1. **Skip building from scratch** — use **GOAD (Game of Active Directory)** or HTB Pro Labs ("Dante", "Offshore", "Zephyr").
2. Practice on **TryHackMe AD paths** (Holo, Wreath) and **HackTheBox AD boxes** (Forest, Active, Sauna, Resolute) before touching real environments.
3. Set up a Kali VM as your attacker and snapshot it before/after each attack.

---

## GOAD — Best Free AD Lab (Recommended)

Multi-domain forest with intentional vulns. The standard practice environment.

```bash
git clone https://github.com/Orange-Cyberdefense/GOAD
cd GOAD
# Choose provider: virtualbox, vmware, proxmox, azure, aws
# Choose lab: GOAD (full, ~6 VMs), GOAD-Light (3 VMs), SCCM, NHA
./goad.sh
# Then in the menu: install <lab> <provider>
```

What you get: 2 domains in a forest (`sevenkingdoms.local` and `north.sevenkingdoms.local`), ~15 vulnerabilities to find including Kerberoasting, AS-REP, NTLM relay, RBCD, AD CS ESC1/ESC4/ESC8.

---

## Minimal Manual Lab (If You Have Limited RAM)

- 1× **Windows Server 2019/2022** → Domain Controller (4 GB RAM)
- 1× **Windows 10/11** → domain-joined workstation (2 GB RAM)
- 1× **Kali Linux** → attacker (2 GB RAM)

Network: Host-only adapter, e.g. `192.168.56.0/24`. Workstation's DNS must point at the DC's IP.

### DC promotion (PowerShell on Windows Server)
```powershell
# Rename + reboot
Rename-Computer -NewName "DC01" -Restart

# Install AD DS
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools

# Promote to DC of a new forest
Install-ADDSForest `
  -DomainName "lab.local" `
  -DomainNetbiosName "LAB" `
  -InstallDns `
  -SafeModeAdministratorPassword (ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force) `
  -Force
```

### Add vulnerabilities to practice against
```powershell
# Kerberoastable service account
New-ADUser -Name "svc_sql" -SamAccountName "svc_sql" `
  -AccountPassword (ConvertTo-SecureString "Summer2024" -AsPlainText -Force) `
  -Enabled $true -PasswordNeverExpires $true
Set-ADUser svc_sql -ServicePrincipalNames @{Add='MSSQLSvc/dc01.lab.local:1433'}

# AS-REP roastable user
New-ADUser -Name "nopreauth" -SamAccountName "nopreauth" `
  -AccountPassword (ConvertTo-SecureString "Password1" -AsPlainText -Force) -Enabled $true
Set-ADAccountControl nopreauth -DoesNotRequirePreAuth $true
```

### Join workstation to domain
```powershell
# On the Windows 10/11 VM
Add-Computer -DomainName "lab.local" -Credential (Get-Credential) -Restart
```

---

## Vulnerable-AD (one-line PowerShell)

If you just want a DC and ~50 vulns added quickly:

```powershell
# On a freshly promoted DC
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/safebuffer/vulnerable-AD/master/vulnad.ps1')
Invoke-VulnAD -UsersLimit 100 -Domain "lab.local"
```

---

## Kali Attacker Setup

```bash
# Update
sudo apt update && sudo apt full-upgrade -y

# Core AD pentest tools
sudo apt install -y \
  bloodhound neo4j \
  impacket-scripts \
  evil-winrm \
  responder \
  ldap-utils \
  smbclient \
  smbmap \
  kerbrute \
  enum4linux-ng \
  john hashcat

# Python tools (use pipx to avoid system Python conflicts)
pipx install netexec        # CrackMapExec successor
pipx install certipy-ad     # AD CS attacks
pipx install bloodhound     # bloodhound-python (Linux collector)
pipx install impacket       # If apt version is old

# BloodHound Community Edition (newer than apt version)
# https://github.com/SpecterOps/BloodHound — see Docker install
```

### Start BloodHound (legacy/neo4j version)
```bash
sudo neo4j start
# Browse http://localhost:7474, login neo4j/neo4j, set new password
bloodhound &
```

### BloodHound CE (recommended, dockerized)
```bash
mkdir bloodhound && cd bloodhound
curl -L https://ghst.ly/getbhce -o docker-compose.yml
docker compose pull && docker compose up
# Browse http://localhost:8080 — initial password in container logs
```

---

## Snapshot Discipline

Before each attack phase, **snapshot every VM**. AD attacks routinely:
- Break domain trust
- Corrupt LSA secrets
- Lock out accounts
- Plant tickets that need a krbtgt reset to clear

Plan on rolling back often.

---

## Background Reading (Read These Eventually)

- **HackTricks AD** → https://book.hacktricks.xyz/windows-hardening/active-directory-methodology
- **The Hacker Recipes** → https://www.thehacker.recipes/
- **adsecurity.org** → Sean Metcalf's research, deep Kerberos content
- **PayloadsAllTheThings / Active Directory Attack** → cheatsheet of cheatsheets
- **SpecterOps blog** → BloodHound, ADCS, advanced research

---

## Certification Path (Optional)

| Tier | Cert | What it covers |
|------|------|----------------|
| Entry | eJPT | Basic pentesting incl. light AD |
| Intermediate | OSCP | Includes AD chain in exam since 2022 |
| Intermediate | PNPT (TCM) | AD-heavy practical exam |
| Advanced | CRTO (ZeroPoint) | Red team ops, C2, evasion |
| Advanced | CRTE (Altered Sec) | Pure AD attacks, multi-forest |
| Master | CRTM, OSEP | Evasion + advanced AD |

---

## Next Step

Lab built, tools installed. → **Phase 1: External Recon** (`01-recon.md`) for real engagements, or jump to **Phase 3: Enumeration** (`03-enumeration.md`) if you already have credentials (typical for CTFs).
