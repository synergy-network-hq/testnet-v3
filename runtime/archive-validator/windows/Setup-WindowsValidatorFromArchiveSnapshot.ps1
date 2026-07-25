param(
  [string]$Workspace,
  [string]$CatalogUrl = "http://73.79.66.255:48640/catalog.json",
  [string]$RuntimePath = "",
  [string]$ZstdPath = "",
  [string]$TarPath = "",
  [string]$SnapshotId = "",
  [switch]$Force,
  [switch]$StartAfterRestore
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($Workspace)) {
  throw "-Workspace is required. Point it at the unpacked Windows validator bundle."
}

$Workspace = [System.IO.Path]::GetFullPath($Workspace)
if (-not (Test-Path -LiteralPath $Workspace)) {
  throw "workspace does not exist: $Workspace"
}

$nodeEnv = Join-Path $Workspace "node.env"
$config = Join-Path $Workspace "config\node.toml"
$nodeCtl = Join-Path $Workspace "nodectl.ps1"
$install = Join-Path $Workspace "install_and_start.ps1"

if (-not (Test-Path -LiteralPath $nodeEnv)) {
  throw "missing node.env in Windows validator workspace: $nodeEnv"
}
if (-not (Test-Path -LiteralPath $config)) {
  throw "missing config\node.toml in Windows validator workspace: $config"
}

if (Test-Path -LiteralPath $nodeCtl) {
  & $nodeCtl setup
} elseif (Test-Path -LiteralPath $install) {
  $previous = $env:INSTALL_ONLY
  try {
    $env:INSTALL_ONLY = "true"
    & $install
  } finally {
    $env:INSTALL_ONLY = $previous
  }
} else {
  throw "workspace must contain nodectl.ps1 or install_and_start.ps1"
}

$restore = Join-Path $PSScriptRoot "Restore-ValidatorSnapshot.ps1"
$restoreArgs = @(
  "-Workspace", $Workspace,
  "-CatalogUrl", $CatalogUrl,
  "-TargetRole", "validator",
  "-SnapshotClass", "validator-pruned"
)
if (-not [string]::IsNullOrWhiteSpace($RuntimePath)) { $restoreArgs += @("-RuntimePath", $RuntimePath) }
if (-not [string]::IsNullOrWhiteSpace($ZstdPath)) { $restoreArgs += @("-ZstdPath", $ZstdPath) }
if (-not [string]::IsNullOrWhiteSpace($TarPath)) { $restoreArgs += @("-TarPath", $TarPath) }
if (-not [string]::IsNullOrWhiteSpace($SnapshotId)) { $restoreArgs += @("-SnapshotId", $SnapshotId) }
if ($Force) { $restoreArgs += "-Force" }
if ($StartAfterRestore) { $restoreArgs += "-StartAfterRestore" }

& $restore @restoreArgs
