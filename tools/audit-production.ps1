param([string]$Imports = "$PSScriptRoot/../validation-artifacts/production-imports.txt")
$ErrorActionPreference = 'Stop'
$production = Join-Path $PSScriptRoot '../src'
$forbidden = '\b(AdjustTokenPrivileges|LookupAccountName[AW]?|LookupAccountSid[AW]?|AuthzInitializeContextFromSid|AuthzInitializeRemoteResourceManager|SetSecurityInfo|SetNamedSecurityInfo[AW]?|SetFileSecurity[AW]?|SetKernelObjectSecurity|SetFileAttributes[AW]?|WriteFile|DeleteFile[AW]?|CreateDirectory[AW]?|RemoveDirectory[AW]?|CreateProcess[AW]?|ShellExecute[AW]?|LogonUser[AW]?|ImpersonateLoggedOnUser|WNet\w*|NetUser\w*|WinHttp\w*|Internet\w*|WSA\w*|connect|socket)\s*\('
foreach ($file in Get-ChildItem -LiteralPath $production -Filter '*.cpp') {
    $source = Get-Content -LiteralPath $file.FullName -Raw
    if ($source -match $forbidden) { throw "Forbidden production call in $($file.Name): $($Matches[0])" }
}
$listing = Get-Content -LiteralPath $Imports -Raw
if ($listing -match '(?im)\b(WS2_32|WINHTTP|WININET|NETAPI32|MPR)\.dll\b') { throw 'Network DLL import found' }
if ($listing -match '(?im)\b(AdjustTokenPrivileges|LookupAccountName[AW]?|LookupAccountSid[AW]?|AuthzInitializeContextFromSid|AuthzInitializeRemoteResourceManager|SetSecurityInfo|SetNamedSecurityInfo[AW]?|WriteFile|DeleteFile[AW]?|CreateProcess[AW]?|ShellExecute[AW]?)\b') { throw 'Forbidden import found' }
foreach ($required in 'AuthzAccessCheck','AuthzInitializeContextFromToken','GetSecurityInfo','CreateFileW','QueryDosDeviceW') {
    if ($listing -notmatch "\b$required\b") { throw "Required import absent: $required" }
}
Write-Output 'PASS production source/import audit: no direct mutation, account-resolution, remote authorization or network calls'
Write-Output 'Scope: direct source/import audit; OS and filesystem-filter behavior is outside this check'
