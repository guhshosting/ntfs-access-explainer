param([string]$Artifacts = "$PSScriptRoot/../validation-artifacts")
$ErrorActionPreference = 'Stop'
$schema = Join-Path $PSScriptRoot '../docs/schema-v1.json'
$files = @(Get-ChildItem -LiteralPath $Artifacts -Filter '*.json')
if ($files.Count -eq 0) { throw 'No JSON artifacts found' }
foreach ($file in $files) {
    $raw = Get-Content -LiteralPath $file.FullName -Raw -Encoding utf8
    $parsed = ConvertFrom-Json -InputObject $raw
    if (-not (Test-Json -Json $raw -SchemaFile $schema -ErrorAction Stop)) { throw "Schema failed: $file" }
    if ($parsed.effective_access.status -eq 'not-calculated' -and $null -ne $parsed.effective_access.granted_mask) { throw 'Unexpected mask' }
    Write-Output "PASS independent JSON parsing/schema: $($file.Name)"
}
# Prove the schema validator rejects a structurally invalid successful report.
$invalid = '{"schema_version":"1.0","tool_version":"1.0.0","aces":[]}'
if (Test-Json -Json $invalid -SchemaFile $schema -ErrorAction SilentlyContinue) { throw 'Schema failed to reject invalid report' }
Write-Output 'PASS negative schema validation'
