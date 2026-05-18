# Phase 1: External Recon & OSINT

> External recon before you have any access. Goal: identify domain names, valid usernames, email format, and entry points.

In CTFs you usually skip this. In real engagements it's where most of the early time goes.

---

## What You're Trying to Learn

1. **Domain name(s)** — e.g. `corp.target.com`, `internal.target.com`
2. **Username format** — `john.doe`, `jdoe`, `j.doe`?
3. **Valid usernames** — to spray passwords against
4. **Entry points** — VPN, RDP web, Citrix, OWA, phishing
5. **Tech stack hints** — Exchange? O365? Citrix? Forefront?

---

## 1. Domain & DNS Discovery

```bash
# Passive subdomain enum (no traffic to target)
subfinder -d target.com -all -o subs.txt
amass enum -passive -d target.com
assetfinder --subs-only target.com

# DNS records that hint at AD
dig +short MX target.com
dig +short TXT target.com                          # SPF often reveals mail infra
nslookup -type=SRV _ldap._tcp.target.com           # if external = misconfigured
nslookup -type=SRV _kerberos._tcp.target.com
```

**Hot subdomains to look for**:
- `autodiscover.*` → Exchange/O365 → AD username format
- `vpn.*`, `gw.*`, `remote.*` → potential entry
- `mail.*`, `owa.*`, `webmail.*` → OWA username enum
- `citrix.*`, `rdp.*`, `rdweb.*` → Windows-facing portals

🟢 **OPSEC**: All passive — no traffic to target's infrastructure.

---

## 2. Email & Employee Harvesting

```bash
# theHarvester
theHarvester -d target.com -b all -l 500 -f harvest.html

# LinkedIn → CrossLinked builds usernames from job titles
crosslinked -f '{first}.{last}@target.com' -t 5 "Target Corp"
# Outputs: john.doe@target.com, sarah.smith@target.com, ...

# Sherlock / Maigret — username reuse research
sherlock john.doe
```

Other sources: Hunter.io, Apollo.io, Snov.io, breaches via dehashed.com / leakcheck.io.

---

## 3. Username Generation

Common AD formats — generate variants per name:

| Format | Example |
|--------|---------|
| first.last | john.doe |
| flast | jdoe |
| firstl | johnd |
| first_last | john_doe |
| f.last | j.doe |
| last.first | doe.john |

```bash
./username-anarchy -i names.txt > usernames.txt
```

---

## 4. Username Validation (Without Lockouts)

### Kerberos pre-auth (when port 88 is exposed externally — rare but happens)
```bash
kerbrute userenum -d target.com --dc 10.10.10.10 usernames.txt
# Returns ONLY valid usernames — does NOT generate failed logon events
```

🟢 **OPSEC**: Kerbrute `userenum` uses AS-REQ responses (KDC_ERR_PREAUTH_REQUIRED vs CLIENT_NOT_FOUND) to validate. Failed logon Event 4625 is **not** generated.

### O365 / Azure AD
```bash
# o365creeper or o365enum — checks if user exists in O365
python3 o365enum.py -u usernames.txt -p validate
```

### OWA timing attacks
Some OWA versions have measurable response-time differences for valid vs invalid users. Tools: `ruler`, `mailsniper`.

---

## 5. Exposed Services & Infrastructure

```bash
# Shodan
shodan search 'org:"Target Corp" port:445'
shodan search 'org:"Target Corp" port:3389 os:Windows'
shodan search 'org:"Target Corp" "RDWeb"'

# Censys
censys search 'services.port:445 and services.banner:"target.com"'

# Active nmap (requires authorization)
nmap -sV -p 80,443,445,3389,5985,5986,8443 vpn.target.com
```

**Windows/AD service fingerprints**:
| Port | Service | Indicates |
|------|---------|-----------|
| 88 | Kerberos | Domain Controller |
| 389 / 636 / 3268 / 3269 | LDAP / LDAPS / Global Catalog | DC |
| 445 | SMB | Windows file sharing |
| 464 | kpasswd | DC |
| 5985 / 5986 | WinRM | Windows remote mgmt |
| 3389 | RDP | Windows host |

---

## 6. Tech Stack Fingerprinting

```bash
# HTTP headers reveal a lot
curl -sI https://owa.target.com | grep -i 'server\|x-'
# X-OWA-Version, X-Powered-By: ASP.NET, Server: Microsoft-IIS/10.0 → Exchange on-prem

# Wappalyzer / WhatWeb
whatweb https://target.com
```

If you find Exchange or AD FS exposed, dig into their version-specific CVEs (ProxyShell, ProxyLogon, ADFS XML signing bugs).

---

## Blue-Team Detection Notes

| Activity | Detection |
|----------|-----------|
| Subdomain enum | Passive — no detection on target side |
| Kerbrute userenum | Some SIEMs alert on volume of AS-REQ from one source IP, but not by default. Pre-auth errors (4768 with result 0x6) per user can be aggregated |
| OWA username spray | Failed auth in OWA logs / IIS logs |
| Shodan/Censys scraping | No direct detection — passive lookups |
| Port scans | NetFlow / NIDS (Suricata) — easy detect with default nmap |

---

## Next Step

Once you have:
- Valid usernames
- An entry point (VPN/RDP/OWA), or stolen creds via phishing
- The internal domain name

→ **Phase 2: Initial Access** (`02-initial-access.md`).
