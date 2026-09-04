$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$pythonPath = Join-Path $repoRoot '.venv\Scripts\python.exe'
$fetchScript = Join-Path $PSScriptRoot 'fetch_electrozone_current.py'
$feedCredentialPath = $env:FIN_ELECTROZONE_FEED_CREDENTIAL_PATH
if ([string]::IsNullOrWhiteSpace($feedCredentialPath)) {
  $feedCredentialPath = Join-Path $env:LOCALAPPDATA 'FinserverOps\Credentials\mks123-electrozone-feed\credential.xml'
}
if (-not (Test-Path -LiteralPath $feedCredentialPath -PathType Leaf)) {
  throw 'Electrozone feed credential file is not configured'
}
if (-not (Test-Path -LiteralPath $pythonPath -PathType Leaf)) {
  throw "Repository Python environment is not installed: $pythonPath"
}
$feedCredential = Import-Clixml $feedCredentialPath
if ($feedCredential -isnot [System.Management.Automation.PSCredential]) {
  throw 'Credential store entry is not a PSCredential'
}
$env:FIN_ELECTROZONE_FEED_USER = $feedCredential.UserName
$env:FIN_ELECTROZONE_FEED_PASS = $feedCredential.GetNetworkCredential().Password
$exitCode = 1
try {
  & $pythonPath $fetchScript
  $exitCode = $LASTEXITCODE
} finally {
  Remove-Item Env:FIN_ELECTROZONE_FEED_USER, Env:FIN_ELECTROZONE_FEED_PASS -ErrorAction SilentlyContinue
}
exit $exitCode
