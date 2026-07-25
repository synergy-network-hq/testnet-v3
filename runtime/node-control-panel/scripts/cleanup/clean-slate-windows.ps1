$ErrorActionPreference = "Stop"

$workspaceRoot = Join-Path $HOME ".synergy-node-control-panel\monitor-workspace"
$legacyRoot = Join-Path $HOME ".synergy-node-monitor\monitor-workspace"
$startupLink = Join-Path ([Environment]::GetFolderPath("Startup")) "Synergy Testnet Agent.cmd"

Write-Host "Cleaning Synergy Node Control Panel artifacts on Windows..."

Get-Process synergy-testnet-agent -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
if (Test-Path $startupLink) {
  Remove-Item $startupLink -Force
}
foreach ($path in @($workspaceRoot, $legacyRoot)) {
  if (Test-Path $path) {
    Remove-Item $path -Recurse -Force
  }
}

Write-Host "Removed local control-panel workspace and startup registration."
Write-Host "Removed local control-panel artifacts only."
