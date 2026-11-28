# Cairn installer for Windows. Installs the cairn-flash CLI as an isolated uv
# tool. Everything Cairn does is read-only until the M6 gate; this script only
# builds and installs the CLI and never touches a device.
$ErrorActionPreference = "Stop"

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Error "git is required. Install Git for Windows and re-run."
}
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    if (Get-Command pip -ErrorAction SilentlyContinue) {
        pip install uv
    } else {
        Write-Error "uv is not installed and pip was not found. Install Python 3.12+ from https://www.python.org and re-run."
    }
}

$repo = if ($PSScriptRoot) { $PSScriptRoot } else { "cairn" }
Push-Location $repo
try {
    uv sync
    uv tool install --from . cairn-flash --force
} finally {
    Pop-Location
}

cairn version
Write-Host ""
Write-Host "Cairn installed. Try: cairn levels ; cairn --help"
Write-Host "Read-only commands are safe on real devices. Writes exist only in the transcript simulator (ADR-027)."
