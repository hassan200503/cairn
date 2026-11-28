# Build the Cairn Windows installer.
#
# Prerequisites: uv (project deps), PyInstaller in the project venv
# (`uv pip install pyinstaller`), and Inno Setup 6 (ISCC.exe).
#
# Usage:  powershell -File tools/installer/build.ps1 [-Iscc "path\to\ISCC.exe"]
#
# The output is tools/installer/installer/CairnSetup-<version>.exe. It ships the
# PyInstaller onefile console build and is unsigned; SmartScreen will warn on
# first run until the publisher certificate exists (see docs/KNOWN_UNKNOWNS.md).

param(
    [string]$Iscc = "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $root

# The version comes from pyproject.toml, one source of truth.
$version = (Select-String -Path pyproject.toml -Pattern '^version = "(.+)"').Matches[0].Groups[1].Value
Write-Host "building Cairn $version"

# 1. PyInstaller onefile console build, with the UI's static assets bundled.
uv run pyinstaller --onefile --name cairn --paths src `
    --add-data "src/cairn/ui/static;cairn/ui/static" `
    --noconfirm tools/installer/launch.py
if ($LASTEXITCODE -ne 0) { throw "pyinstaller failed" }

# Smoke-check the packaged binary before wrapping it.
& dist\cairn.exe version
if ($LASTEXITCODE -ne 0) { throw "packaged cairn.exe does not run" }

# 2. Inno Setup wrapper.
New-Item -ItemType Directory -Force -Path tools/installer/dist | Out-Null
Copy-Item dist\cairn.exe tools\installer\dist\cairn.exe -Force
& $Iscc /DCairnVersion=$version tools/installer/cairn.iss
if ($LASTEXITCODE -ne 0) { throw "ISCC failed" }

Write-Host "installer: tools/installer/installer/CairnSetup-$version.exe"
