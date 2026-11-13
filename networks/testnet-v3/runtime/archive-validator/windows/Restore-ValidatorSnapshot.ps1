param(
  [string]$Workspace = (Get-Location).Path,
  [string]$CatalogUrl = "http://73.79.66.255:48640/catalog.json",
  [string]$TargetRole = "validator",
  [string]$SnapshotClass = "",
  [string]$SnapshotId = "",
  [int]$ChainId = 1264,
  [string]$NetworkId = "synergy-testnet-v3",
  [string]$GenesisHash = "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789",
  [string]$RuntimePath = "",
  [string]$ZstdPath = "",
  [string]$TarPath = "",
  [switch]$SkipRuntimeVerify,
  [switch]$Force,
  [switch]$StartAfterRestore
)

$ErrorActionPreference = "Stop"

$RoleToClass = @{
  validator = "validator-pruned"
  onboarding_validator = "validator-pruned"
  quarantined_validator = "validator-pruned"
  rpc = "support-rpc"
  rpc_gateway = "support-rpc"
  relayer = "support-relayer"
  observer = "support-observer"
  indexer = "indexer-replay"
  explorer = "indexer-replay"
  atlas_indexer = "indexer-replay"
  explorer_indexer = "indexer-replay"
  archive = "archive-full"
  archive_validator = "archive-full"
  snapshot_authority = "archive-full"
}

$ClassToRoles = @{
  "validator-pruned" = @("validator", "onboarding_validator", "quarantined_validator")
  "support-rpc" = @("rpc", "rpc_gateway")
  "support-relayer" = @("relayer")
  "support-observer" = @("observer")
  "indexer-replay" = @("indexer", "explorer", "atlas_indexer", "explorer_indexer")
  "indexer-full" = @("indexer", "explorer", "atlas_indexer", "explorer_indexer")
  "archive-full" = @("archive", "archive_validator", "snapshot_authority")
  "archive-bootstrap" = @("archive", "archive_validator", "snapshot_authority")
}

$AllowedStateFiles = @(
  "chain.json",
  "committed_blocks.jsonl",
  "canonical_locks.json",
  "committed_qcs.json",
  "committed_qcs.jsonl",
  "dag_state.json",
  "validator_registry.json",
  "token_state.json",
  "account_state.json",
  "state_checkpoint.json"
)

function Resolve-RequiredFullPath([string]$Path) {
  return [System.IO.Path]::GetFullPath($Path)
}

function Read-JsonFile([string]$Path) {
  return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Write-JsonFile([string]$Path, $Value) {
  $parent = Split-Path -Parent $Path
  if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
  $Value | ConvertTo-Json -Depth 32 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Get-Sha256([string]$Path) {
  return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Assert-Sha256([string]$Path, [string]$Expected, [string]$Label) {
  if ([string]::IsNullOrWhiteSpace($Expected)) {
    throw "$Label is missing expected sha256"
  }
  $actual = Get-Sha256 $Path
  if ($actual -ne $Expected.ToLowerInvariant()) {
    throw "$Label sha256 mismatch: expected $Expected actual $actual path=$Path"
  }
}

function Resolve-Tool([string]$ExplicitPath, [string[]]$Names, [string]$Label) {
  if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
    if (-not (Test-Path -LiteralPath $ExplicitPath)) {
      throw "$Label not found at $ExplicitPath"
    }
    return (Resolve-Path -LiteralPath $ExplicitPath).Path
  }
  foreach ($name in $Names) {
    $command = Get-Command $name -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($command) { return $command.Source }
  }
  throw "$Label is required. Install it or pass an explicit path."
}

function Join-ArchiveUrl([string]$RelativePath) {
  $base = [Uri]$CatalogUrl
  $baseText = $base.AbsoluteUri
  $prefix = $baseText.Substring(0, $baseText.LastIndexOf("/") + 1)
  return ([Uri]::new([Uri]$prefix, $RelativePath)).AbsoluteUri
}

function Receive-ArchiveFile([string]$RelativePath, [string]$OutFile) {
  $url = Join-ArchiveUrl $RelativePath
  $parent = Split-Path -Parent $OutFile
  if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
  Invoke-WebRequest -Uri $url -OutFile $OutFile -UseBasicParsing
  return $url
}

function Assert-SafeRelativeStatePath([string]$RelativePath) {
  if ([string]::IsNullOrWhiteSpace($RelativePath)) {
    throw "snapshot manifest contains an empty relative_path"
  }
  if ([System.IO.Path]::IsPathRooted($RelativePath)) {
    throw "snapshot state path must be relative: $RelativePath"
  }
  $parts = $RelativePath -split "[/\\]"
  if ($parts | Where-Object { $_ -eq ".." -or $_ -eq "" }) {
    throw "snapshot state path contains unsafe traversal: $RelativePath"
  }
  if ($parts.Count -ne 1) {
    throw "snapshot state path must stay at the data root on Windows: $RelativePath"
  }
  $name = [System.IO.Path]::GetFileName($RelativePath)
  if ($AllowedStateFiles -notcontains $name) {
    throw "snapshot state path is not launch-approved: $RelativePath"
  }
}

function Get-RunningNodeProcess([string]$Root) {
  $pidFile = Join-Path $Root "data\node.pid"
  if (-not (Test-Path -LiteralPath $pidFile)) { return $null }
  $pidText = Get-Content -LiteralPath $pidFile -ErrorAction SilentlyContinue | Select-Object -First 1
  if ([string]::IsNullOrWhiteSpace($pidText)) { return $null }
  return Get-Process -Id ([int]$pidText) -ErrorAction SilentlyContinue
}

function Resolve-Runtime([string]$Root) {
  if (-not [string]::IsNullOrWhiteSpace($RuntimePath)) {
    if (-not (Test-Path -LiteralPath $RuntimePath)) { throw "runtime not found: $RuntimePath" }
    return (Resolve-Path -LiteralPath $RuntimePath).Path
  }
  foreach ($candidate in @(
    (Join-Path $Root "bin\synergy-testnet-windows-amd64.exe"),
    (Join-Path $Root "bin\synergy-node.exe"),
    (Join-Path $Root "bin\synergy-testnet.exe")
  )) {
    if (Test-Path -LiteralPath $candidate) { return (Resolve-Path -LiteralPath $candidate).Path }
  }
  throw "Windows Synergy runtime not found under $Root\bin. Pass -RuntimePath."
}

function Invoke-RuntimeSnapshotVerify(
  [string]$Runtime,
  [string]$Root,
  [string]$Manifest,
  [string]$SnapshotRoot,
  [string]$Class,
  [string]$Role,
  [string]$OutputPath
) {
  $previousProjectRoot = $env:SYNERGY_PROJECT_ROOT
  $previousConfigPath = $env:SYNERGY_CONFIG_PATH
  try {
    $env:SYNERGY_PROJECT_ROOT = $Root
    $env:SYNERGY_CONFIG_PATH = Join-Path $Root "config\node.toml"
    $args = @(
      "verify-snapshot",
      "--manifest", $Manifest,
      "--snapshot-root", $SnapshotRoot,
      "--snapshot-class", $Class,
      "--target-role", $Role,
      "--chain-id", "$ChainId",
      "--network-id", $NetworkId
    )
    $output = & $Runtime @args 2>&1
    $exitCode = $LASTEXITCODE
    $text = ($output | Out-String)
    Set-Content -LiteralPath $OutputPath -Value $text -Encoding UTF8
    if ($exitCode -ne 0) {
      throw "runtime verify-snapshot exited $exitCode. See $OutputPath"
    }
    try {
      $json = $text | ConvertFrom-Json
      if (($json.PSObject.Properties.Name -contains "success") -and $json.success -ne $true) {
        throw "runtime verify-snapshot returned success=false. See $OutputPath"
      }
      if (($json.PSObject.Properties.Name -contains "fail_closed") -and $json.fail_closed -eq $true) {
        throw "runtime verify-snapshot failed closed. See $OutputPath"
      }
    } catch {
      throw
    }
  } finally {
    $env:SYNERGY_PROJECT_ROOT = $previousProjectRoot
    $env:SYNERGY_CONFIG_PATH = $previousConfigPath
  }
}

$Workspace = Resolve-RequiredFullPath $Workspace
if (-not (Test-Path -LiteralPath $Workspace)) {
  throw "workspace does not exist: $Workspace"
}
if (-not (Test-Path -LiteralPath (Join-Path $Workspace "config\node.toml"))) {
  throw "workspace is missing config\node.toml: $Workspace"
}

$TargetRole = $TargetRole.Trim().ToLowerInvariant().Replace("-", "_")
if (-not $RoleToClass.ContainsKey($TargetRole)) {
  throw "unsupported target role: $TargetRole"
}
if ([string]::IsNullOrWhiteSpace($SnapshotClass)) {
  $SnapshotClass = $RoleToClass[$TargetRole]
}
if (-not $ClassToRoles.ContainsKey($SnapshotClass)) {
  throw "unsupported snapshot class: $SnapshotClass"
}
if ($ClassToRoles[$SnapshotClass] -notcontains $TargetRole) {
  throw "snapshot class $SnapshotClass is not compatible with target role $TargetRole"
}

$running = Get-RunningNodeProcess $Workspace
if ($running -and -not $Force) {
  throw "node appears to be running as PID $($running.Id). Stop it first or pass -Force."
}
if ($running -and $Force) {
  Stop-Process -Id $running.Id -Force
}

$zstd = Resolve-Tool $ZstdPath @("zstd.exe", "zstd") "zstd"
$tar = Resolve-Tool $TarPath @("tar.exe", "tar") "tar"
$runtime = if ($SkipRuntimeVerify) { "" } else { Resolve-Runtime $Workspace }

$catalog = Invoke-RestMethod -Uri $CatalogUrl -Method Get
if ([int]$catalog.chain_id -ne $ChainId -or [string]$catalog.network_id -ne $NetworkId) {
  throw "catalog chain/network mismatch"
}
if ([string]$catalog.genesis_hash -ne $GenesisHash) {
  throw "catalog genesis mismatch"
}

$candidates = @($catalog.snapshots) | Where-Object {
  $_.status -eq "published" -and
  $_.snapshot_class -eq $SnapshotClass -and
  @($_.allowed_roles) -contains $TargetRole -and
  [int]$_.chain_id -eq $ChainId -and
  $_.network_id -eq $NetworkId -and
  $_.genesis_hash -eq $GenesisHash -and
  $_.verification_status -eq "green"
}
if (-not [string]::IsNullOrWhiteSpace($SnapshotId)) {
  $candidates = @($candidates) | Where-Object { $_.snapshot_id -eq $SnapshotId }
}
if (-not $candidates -or @($candidates).Count -eq 0) {
  throw "no published green snapshot found for class=$SnapshotClass role=$TargetRole"
}
$selected = @($candidates) |
  Sort-Object @{ Expression = { [int64]$_.height }; Descending = $true }, @{ Expression = { [int64]$_.created_at }; Descending = $true } |
  Select-Object -First 1

$SnapshotId = [string]$selected.snapshot_id
$incomingRoot = Join-Path $Workspace "data\incoming-snapshots\$SnapshotId"
$extractRoot = Join-Path $incomingRoot "extract"
$evidenceRoot = Join-Path $Workspace "data\snapshot-restore-evidence\$(Get-Date -AsUTC -Format 'yyyyMMddTHHmmssZ')-$SnapshotId"
New-Item -ItemType Directory -Force -Path $incomingRoot, $extractRoot, $evidenceRoot | Out-Null
Write-JsonFile (Join-Path $evidenceRoot "catalog-entry.json") $selected

$relativeBase = "testnet-1264/$SnapshotClass/$SnapshotId"
$distributionPath = Join-Path $incomingRoot "distribution-manifest.json"
$distributionSigPath = Join-Path $incomingRoot "distribution-manifest.sig"
Receive-ArchiveFile "$relativeBase/distribution-manifest.json" $distributionPath | Out-Null
Receive-ArchiveFile "$relativeBase/distribution-manifest.sig" $distributionSigPath | Out-Null
$distribution = Read-JsonFile $distributionPath

if ($distribution.status -ne "published") { throw "distribution is not published" }
if ([int]$distribution.chain_id -ne $ChainId -or [string]$distribution.network_id -ne $NetworkId) {
  throw "distribution chain/network mismatch"
}
if ([string]$distribution.genesis_hash -ne $GenesisHash) {
  throw "distribution genesis mismatch"
}
if (@($distribution.allowed_roles) -notcontains $TargetRole) {
  throw "distribution does not allow target role $TargetRole"
}
if (@($distribution.supported_receiver_operating_systems) -notcontains "windows") {
  throw "distribution does not declare Windows receiver support"
}

$sourceManifestPath = Join-Path $incomingRoot "source-snapshot-manifest.json"
Receive-ArchiveFile "$relativeBase/$($distribution.source_manifest)" $sourceManifestPath | Out-Null
Assert-Sha256 $sourceManifestPath ([string]$distribution.source_manifest_sha256) "source manifest"

$archivePath = Join-Path $incomingRoot $distribution.archive_filename
if (Test-Path -LiteralPath $archivePath) { Remove-Item -LiteralPath $archivePath -Force }
$archiveStream = [System.IO.File]::Open($archivePath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
try {
  foreach ($chunk in @($distribution.chunks)) {
    $chunkPath = Join-Path $incomingRoot $chunk.name
    Receive-ArchiveFile "$relativeBase/$($chunk.name)" $chunkPath | Out-Null
    Assert-Sha256 $chunkPath ([string]$chunk.sha256) "chunk $($chunk.name)"
    $chunkStream = [System.IO.File]::OpenRead($chunkPath)
    try {
      $chunkStream.CopyTo($archiveStream)
    } finally {
      $chunkStream.Dispose()
    }
  }
} finally {
  $archiveStream.Dispose()
}
Assert-Sha256 $archivePath ([string]$distribution.archive_sha256) "reassembled archive"

$tarPath = Join-Path $incomingRoot "$($distribution.archive_filename).tar"
if (Test-Path -LiteralPath $tarPath) { Remove-Item -LiteralPath $tarPath -Force }
& $zstd -d -f $archivePath -o $tarPath
if ($LASTEXITCODE -ne 0) { throw "zstd extraction failed for $archivePath" }
& $tar -xf $tarPath -C $extractRoot
if ($LASTEXITCODE -ne 0) { throw "tar extraction failed for $tarPath" }

$snapshotRoots = @(Get-ChildItem -LiteralPath $extractRoot -Directory | Where-Object {
  Test-Path -LiteralPath (Join-Path $_.FullName $distribution.source_manifest)
})
if ($snapshotRoots.Count -ne 1) {
  throw "snapshot extraction did not produce exactly one snapshot root"
}
$snapshotRoot = $snapshotRoots[0].FullName
$extractedManifest = Join-Path $snapshotRoot $distribution.source_manifest
$signedManifest = Read-JsonFile $extractedManifest
$manifest = if ($signedManifest.PSObject.Properties.Name -contains "manifest") { $signedManifest.manifest } else { $signedManifest }
if ([int]$manifest.chain_id -ne $ChainId -or [string]$manifest.network_id -ne $NetworkId) {
  throw "source snapshot manifest chain/network mismatch"
}
if ([string]$manifest.genesis_hash -ne $GenesisHash) {
  throw "source snapshot manifest genesis mismatch"
}
if ([string]$manifest.snapshot_class -ne $SnapshotClass) {
  throw "source snapshot class mismatch"
}
if (@($manifest.allowed_restore_roles) -notcontains $TargetRole) {
  throw "source snapshot does not allow target role $TargetRole"
}

foreach ($entry in @($manifest.files)) {
  Assert-SafeRelativeStatePath ([string]$entry.relative_path)
  $source = Join-Path $snapshotRoot ([string]$entry.relative_path)
  if (-not (Test-Path -LiteralPath $source)) {
    throw "snapshot state file is missing: $($entry.relative_path)"
  }
  Assert-Sha256 $source ([string]$entry.sha256) "state file $($entry.relative_path)"
}

if (-not $SkipRuntimeVerify) {
  Invoke-RuntimeSnapshotVerify `
    -Runtime $runtime `
    -Root $Workspace `
    -Manifest $extractedManifest `
    -SnapshotRoot $snapshotRoot `
    -Class $SnapshotClass `
    -Role $TargetRole `
    -OutputPath (Join-Path $evidenceRoot "runtime-verify-snapshot.json")
}

$targetData = Join-Path $Workspace "data"
$backupDir = Join-Path $evidenceRoot "target-before"
New-Item -ItemType Directory -Force -Path $targetData, $backupDir | Out-Null
foreach ($name in $AllowedStateFiles) {
  $target = Join-Path $targetData $name
  if (Test-Path -LiteralPath $target) {
    Copy-Item -LiteralPath $target -Destination (Join-Path $backupDir $name) -Force
  }
}
foreach ($entry in @($manifest.files)) {
  $relative = [string]$entry.relative_path
  Copy-Item -LiteralPath (Join-Path $snapshotRoot $relative) -Destination (Join-Path $targetData $relative) -Force
}

$report = [ordered]@{
  ok = $true
  typed_status = "WINDOWS_SNAPSHOT_RESTORED"
  workspace = $Workspace
  target_role = $TargetRole
  snapshot_class = $SnapshotClass
  snapshot_id = $SnapshotId
  snapshot_height = [int64]$manifest.snapshot_height
  snapshot_hash = [string]$manifest.snapshot_block_hash
  chain_id = $ChainId
  network_id = $NetworkId
  genesis_hash = $GenesisHash
  catalog_url = $CatalogUrl
  incoming_path = $incomingRoot
  extracted_snapshot_root = $snapshotRoot
  evidence_path = $evidenceRoot
  runtime_verification_skipped = [bool]$SkipRuntimeVerify
  restored_files = @($manifest.files | ForEach-Object { $_.relative_path })
  next_required_action = "run nodectl.ps1 sync or nodectl.ps1 start after confirming peer connectivity"
}
Write-JsonFile (Join-Path $evidenceRoot "restore-report.json") $report
Write-Host "windows_snapshot_restore_ok=true"
Write-Host "snapshot_id=$SnapshotId"
Write-Host "snapshot_height=$($manifest.snapshot_height)"
Write-Host "evidence_path=$evidenceRoot"

if ($StartAfterRestore) {
  $nodeCtl = Join-Path $Workspace "nodectl.ps1"
  if (-not (Test-Path -LiteralPath $nodeCtl)) {
    throw "-StartAfterRestore requested but nodectl.ps1 was not found in $Workspace"
  }
  & $nodeCtl sync
}
