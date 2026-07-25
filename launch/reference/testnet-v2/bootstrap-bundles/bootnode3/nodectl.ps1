param(
  [Parameter(Position = 0)]
  [ValidateSet("start", "stop", "restart", "sync", "status", "logs", "info", "setup", "install_node", "bootstrap_node", "reset_chain", "export_logs", "view_chain_data", "export_chain_data")]
  [string]$Action = "status",
  [switch]$Follow
)

$ErrorActionPreference = "Stop"

$BaseDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$EnvPath = Join-Path $BaseDir "node.env"
$NodeEnv = @{}

if (-not (Test-Path $EnvPath)) {
  throw "Missing node.env at $EnvPath"
}

Get-Content $EnvPath | ForEach-Object {
  if ($_ -match '^\s*$' -or $_ -match '^\s*#') { return }
  $parts = $_ -split '=', 2
  if ($parts.Count -eq 2) {
    $NodeEnv[$parts[0].Trim()] = $parts[1].Trim()
  }
}

function Get-NodeEnvValue([string]$Name) {
  if ($NodeEnv.ContainsKey($Name)) { return $NodeEnv[$Name] }
  return ""
}

$DataDir = Join-Path $BaseDir "data"
$PidFile = Join-Path $DataDir "node.pid"
$OutFile = Join-Path $DataDir "logs/node.out"
$LogsDir = Join-Path $DataDir "logs"
$ChainDir = Join-Path $DataDir "chain"
$InstallStampFile = Join-Path $DataDir ".installed_at"

function Test-NodeRunning {
  if (-not (Test-Path $PidFile)) { return $false }
  $pidValue = (Get-Content $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1)
  if (-not $pidValue) { return $false }
  return $null -ne (Get-Process -Id $pidValue -ErrorAction SilentlyContinue)
}

function Start-Node { & (Join-Path $BaseDir "install_and_start.ps1") }
function Setup-Node {
  $env:INSTALL_ONLY = "true"
  & (Join-Path $BaseDir "install_and_start.ps1")
}
function Install-Node {
  $env:INSTALL_ONLY = "true"
  & (Join-Path $BaseDir "install_and_start.ps1")
}
function Bootstrap-Node { & (Join-Path $BaseDir "install_and_start.ps1") }

# Sync only — download all missing blocks from peers, then start the node when
# catch-up completes. Intended for late-joining nodes or nodes that have been
# offline for a long time.
function Sync-Node {
  $env:SYNC_ONLY = "true"
  $env:AUTO_START_AFTER_SYNC = "true"
  if (-not $env:PRESTART_SYNC_TIMEOUT_SECS) { $env:PRESTART_SYNC_TIMEOUT_SECS = "7200" }
  & (Join-Path $BaseDir "install_and_start.ps1")
}

function Stop-Node {
  if (-not (Test-NodeRunning)) {
    Write-Host "$($NodeEnv['NODE_SLOT_ID']) is not running"
    if (Test-Path $PidFile) { Remove-Item $PidFile -Force }
    return
  }

  $pidValue = Get-Content $PidFile | Select-Object -First 1
  Stop-Process -Id $pidValue -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 2
  if (Get-Process -Id $pidValue -ErrorAction SilentlyContinue) {
    Stop-Process -Id $pidValue -Force -ErrorAction SilentlyContinue
  }
  if (Test-Path $PidFile) { Remove-Item $PidFile -Force }
  Write-Host "Stopped $($NodeEnv['NODE_SLOT_ID'])"
}

function Reset-Chain {
  Stop-Node
  foreach ($target in @(
    $ChainDir,
    (Join-Path $DataDir "testnet\$($NodeEnv['NODE_SLOT_ID'])\chain"),
    (Join-Path $DataDir "testnet\$($NodeEnv['NODE_SLOT_ID'])\logs"),
    (Join-Path $DataDir "chain.json"),
    (Join-Path $DataDir "token_state.json"),
    (Join-Path $DataDir "validator_registry.json"),
    (Join-Path $DataDir "synergy-testnet.pid"),
    (Join-Path $DataDir ".reset_flag"),
    $PidFile
  )) {
    if (Test-Path $target) {
      Remove-Item $target -Recurse -Force
    }
  }
  New-Item -ItemType Directory -Force -Path $ChainDir, $LogsDir | Out-Null
  New-Item -ItemType Directory -Force -Path (Join-Path $DataDir "testnet\$($NodeEnv['NODE_SLOT_ID'])\chain") | Out-Null
  New-Item -ItemType Directory -Force -Path (Join-Path $DataDir "testnet\$($NodeEnv['NODE_SLOT_ID'])\logs") | Out-Null
  Write-Host "Reset chain state for $($NodeEnv['NODE_SLOT_ID']). Node remains stopped."
}

function Status-Node {
  if (Test-NodeRunning) {
    $pidValue = Get-Content $PidFile | Select-Object -First 1
    Write-Host "$($NodeEnv['NODE_SLOT_ID']) is running (PID $pidValue)"
  } else {
    Write-Host "$($NodeEnv['NODE_SLOT_ID']) is stopped"
  }
}

function Logs-Node {
  if (-not (Test-Path $OutFile)) {
    Write-Host "Log file not found: $OutFile"
    return
  }
  if ($Follow) {
    Get-Content -Path $OutFile -Tail 120 -Wait
  } else {
    Get-Content -Path $OutFile -Tail 120
  }
}

function New-ExportDirectory {
  $exportDir = Join-Path $BaseDir "exports"
  New-Item -ItemType Directory -Force -Path $exportDir | Out-Null
  return $exportDir
}

function Export-Logs {
  $exportDir = New-ExportDirectory
  $archive = Join-Path $exportDir "$($NodeEnv['NODE_SLOT_ID'])-logs-$(Get-Date -AsUTC -Format 'yyyyMMddTHHmmssZ').zip"
  Compress-Archive -Path $LogsDir -DestinationPath $archive -Force
  Write-Host "Exported logs to $archive"
}

function View-ChainData {
  if (-not (Test-Path $ChainDir)) {
    Write-Host "Chain directory not found: $ChainDir"
    return
  }
  Get-ChildItem $ChainDir -Recurse -File -ErrorAction SilentlyContinue |
    Sort-Object Length -Descending |
    Select-Object -First 20 FullName,Length,LastWriteTime |
    Format-Table -AutoSize
}

function Export-ChainData {
  $exportDir = New-ExportDirectory
  $archive = Join-Path $exportDir "$($NodeEnv['NODE_SLOT_ID'])-chain-$(Get-Date -AsUTC -Format 'yyyyMMddTHHmmssZ').zip"
  Compress-Archive -Path $ChainDir -DestinationPath $archive -Force
  Write-Host "Exported chain data to $archive"
}

function Info-Node {
  $binary = Get-ChildItem (Join-Path $BaseDir "bin") -Filter "synergy-testnet*" -File -ErrorAction SilentlyContinue |
    Sort-Object Name |
    Select-Object -First 1 -ExpandProperty FullName
  Write-Host "Node Slot ID: $(Get-NodeEnvValue 'NODE_SLOT_ID')"
  Write-Host "Node ID: $(Get-NodeEnvValue 'NODE_ALIAS')"
  Write-Host "Role: $(Get-NodeEnvValue 'ROLE')"
  Write-Host "Node Type: $(Get-NodeEnvValue 'NODE_TYPE')"
  Write-Host "Address Class: $(Get-NodeEnvValue 'ADDRESS_CLASS')"
  Write-Host "Address: $(Get-NodeEnvValue 'NODE_ADDRESS')"
  Write-Host "Monitor Host: $(Get-NodeEnvValue 'MONITOR_HOST')"
  Write-Host "Inventory Address: $(Get-NodeEnvValue 'MANAGEMENT_HOST')"
  Write-Host "Transport: $(Get-NodeEnvValue 'NETWORK_TRANSPORT')"
  Write-Host "P2P: $(Get-NodeEnvValue 'P2P_PORT')"
  Write-Host "RPC: $(Get-NodeEnvValue 'RPC_PORT')"
  Write-Host "WS: $(Get-NodeEnvValue 'WS_PORT')"
  Write-Host "gRPC: $(Get-NodeEnvValue 'GRPC_PORT')"
  Write-Host "Discovery: $(Get-NodeEnvValue 'DISCOVERY_PORT')"
  Write-Host "Binary: $binary"
  Write-Host "Config: $(Join-Path $BaseDir 'config/node.toml')"
}

switch ($Action) {
  "start"   { Start-Node }
  "setup"   { Setup-Node }
  "install_node" { Install-Node }
  "bootstrap_node" { Bootstrap-Node }
  "stop"    { Stop-Node }
  "restart" { Stop-Node; Start-Node }
  "sync"    { Sync-Node }
  "reset_chain" { Reset-Chain }
  "status"  { Status-Node }
  "logs"    { Logs-Node }
  "export_logs" { Export-Logs }
  "view_chain_data" { View-ChainData }
  "export_chain_data" { Export-ChainData }
  "info"    { Info-Node }
}
