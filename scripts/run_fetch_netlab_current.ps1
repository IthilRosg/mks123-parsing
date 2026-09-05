[CmdletBinding()]
param(
    [ValidateSet("price", "properties", "all")]
    [string]$Kind = "all",
    [string]$RawRoot
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
if (-not $RawRoot) {
    $RawRoot = Join-Path $ProjectRoot "raw"
}
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$Fetcher = Join-Path $PSScriptRoot "fetch_netlab_current.py"

if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    throw "Project Python is missing. Run: uv sync --frozen"
}

if ($Kind -eq "price" -or $Kind -eq "all") {
    & $Python $Fetcher --kind price --raw-root $RawRoot
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
if ($Kind -eq "properties" -or $Kind -eq "all") {
    & $Python $Fetcher --kind properties --raw-root $RawRoot
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
