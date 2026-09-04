[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('electrozone', 'vetkom')]
  [string]$Supplier
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$relativePath = switch ($Supplier) {
  'electrozone' { 'mks123-electrozone-feed\credential.xml' }
  'vetkom'     { 'mks123-vetkom-b2b\credential.xml' }
}

$target = Join-Path $env:LOCALAPPDATA (Join-Path 'FinserverOps\Credentials' $relativePath)
$targetDirectory = Split-Path -Parent $target
$temp = Join-Path $targetDirectory ('.credential-{0}-{1}.tmp' -f $PID, ([guid]::NewGuid().ToString('N')))

try {
  if (Test-Path -LiteralPath $target -PathType Leaf) {
    throw "Credential entry already exists: $target. Remove it manually before replacing it."
  }

  New-Item -ItemType Directory -Path $targetDirectory -Force | Out-Null
  $userName = Read-Host "${Supplier} username"
  if ([string]::IsNullOrWhiteSpace($userName)) {
    throw 'Username must not be empty.'
  }
  $securePassword = Read-Host "${Supplier} password (hidden input)" -AsSecureString
  $credential = [System.Management.Automation.PSCredential]::new($userName, $securePassword)

  # Export-Clixml encrypts SecureString fields with the current Windows user's DPAPI.
  Export-Clixml -LiteralPath $temp -InputObject $credential -Force
  [System.IO.File]::Move($temp, $target, $false)
  Write-Output "Credential entry created: $target"
  Write-Output 'Password value was not printed, logged, or placed in a command-line argument.'
}
finally {
  if (Test-Path -LiteralPath $temp -PathType Leaf) {
    Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
  }
}
