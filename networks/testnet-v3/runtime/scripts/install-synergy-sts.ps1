param(
    [string]$InstallDir = $(if ($env:SYNERGY_STS_INSTALL_DIR) { $env:SYNERGY_STS_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "Synergy\bin" }),
    [string]$Version = $(if ($env:SYNERGY_STS_VERSION) { $env:SYNERGY_STS_VERSION } else { "latest" }),
    [string]$Repo = $(if ($env:SYNERGY_STS_GITHUB_REPO) { $env:SYNERGY_STS_GITHUB_REPO } else { "synergy-network-hq/synergy-sts-cli-releases" }),
    [string]$Target = $(if ($env:SYNERGY_STS_TARGET) { $env:SYNERGY_STS_TARGET } else { "windows-amd64" }),
    [string]$FromSource = "",
    [string]$FromFile = "",
    [string]$Url = "",
    [string]$Sha256 = $(if ($env:SYNERGY_STS_SHA256) { $env:SYNERGY_STS_SHA256 } else { "" }),
    [switch]$SkipSha256,
    [switch]$AddToPath,
    [switch]$NoPathCheck,
    [switch]$NoLocked,
    [switch]$DryRun,
    [switch]$Help
)

$ErrorActionPreference = "Stop"
$BinName = "synergy-sts"

function Show-Usage {
    Write-Host @"
Install the Synergy Token System CLI.

Usage:
  powershell -ExecutionPolicy Bypass -File .\scripts\install-synergy-sts.ps1 [options]

Install modes:
  -FromSource <dir>       Build synergy-sts from a local synergy-testnet checkout.
  -FromFile <path>        Install an existing synergy-sts.exe binary.
  -Url <url>              Download a binary from an explicit URL.
  -Version <tag|latest>   GitHub release tag to install. Default: latest.
  -Repo <owner/repo>      GitHub repository for release assets. Default: synergy-network-hq/synergy-sts-cli-releases.

Install options:
  -InstallDir <dir>       Directory for the installed binary. Default: %LOCALAPPDATA%\Synergy\bin.
  -Target <platform>      Release asset platform. Default: windows-amd64.
  -Sha256 <hex>           Expected binary SHA-256 for -Url or -FromFile.
  -SkipSha256             Do not require release .sha256 verification.
  -AddToPath              Add the install directory to the user PATH.
  -NoPathCheck            Skip PATH warnings.
  -NoLocked               Build from source without cargo --locked.
  -DryRun                 Print actions without installing.
  -Help                   Show this help.

Examples:
  .\scripts\install-synergy-sts.ps1 -FromSource .
  .\scripts\install-synergy-sts.ps1 -Version synergy-sts-v15.0.11 -AddToPath
"@
}

function Fail($Message) {
    throw "install-synergy-sts: $Message"
}

function Info($Message) {
    Write-Host "install-synergy-sts: $Message"
}

function Test-RepoRoot($Dir) {
    return (Test-Path (Join-Path $Dir "Cargo.toml")) -and
        (Test-Path (Join-Path $Dir "src\Cargo.toml")) -and
        (Test-Path (Join-Path $Dir "src\bin\synergy-sts.rs"))
}

function Get-AssetName($Platform) {
    if ($Platform.StartsWith("windows-")) {
        return "$BinName-$Platform.exe"
    }
    return "$BinName-$Platform"
}

function Get-ReleaseUrl($Asset) {
    if ($Version -eq "latest") {
        return "https://github.com/$Repo/releases/latest/download/$Asset"
    }
    return "https://github.com/$Repo/releases/download/$Version/$Asset"
}

function Download-File($SourceUrl, $Dest) {
    Invoke-WebRequest -Uri $SourceUrl -OutFile $Dest -UseBasicParsing
}

function Get-Sha256($Path) {
    return (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLowerInvariant()
}

function Verify-Sha256($Path, $Expected) {
    if ([string]::IsNullOrWhiteSpace($Expected)) {
        Fail "missing expected SHA-256"
    }
    $Actual = Get-Sha256 $Path
    if ($Actual -ne $Expected.ToLowerInvariant()) {
        Fail "SHA-256 mismatch for $Path`: expected $Expected, got $Actual"
    }
}

function Read-SidecarSha($Path) {
    $Line = Get-Content -Path $Path -TotalCount 1
    if ([string]::IsNullOrWhiteSpace($Line)) {
        Fail "empty SHA-256 sidecar: $Path"
    }
    return ($Line -split "\s+")[0]
}

if ($Help) {
    Show-Usage
    exit 0
}

$ModeCount = 0
if ($FromSource) { $ModeCount++ }
if ($FromFile) { $ModeCount++ }
if ($Url) { $ModeCount++ }
if ($ModeCount -gt 1) {
    Fail "choose only one of -FromSource, -FromFile, or -Url"
}

$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("synergy-sts-install-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $TempDir | Out-Null

try {
    $SourceBinary = ""

    if ($FromFile) {
        if (!(Test-Path $FromFile)) {
            Fail "-FromFile does not exist: $FromFile"
        }
        $SourceBinary = (Resolve-Path $FromFile).Path
        if ($Sha256) {
            Verify-Sha256 $SourceBinary $Sha256
        }
    } elseif ($Url) {
        $SourceBinary = Join-Path $TempDir "$BinName.exe"
        if ($DryRun) {
            Info "would download $Url"
        } else {
            Download-File $Url $SourceBinary
            if ($Sha256) {
                Verify-Sha256 $SourceBinary $Sha256
            } elseif (-not $SkipSha256) {
                Info "warning: -Url install has no -Sha256; use -Sha256 for pinned installs"
            }
        }
    } elseif ($FromSource) {
        $SourceDir = $FromSource
        if (!(Test-RepoRoot $SourceDir)) {
            Fail "not a synergy-testnet repo root: $SourceDir"
        }
        if ($DryRun) {
            Info "would build $BinName from $SourceDir"
            $SourceBinary = Join-Path $SourceDir "target\release\$BinName.exe"
        } else {
            $Cargo = Get-Command cargo -ErrorAction SilentlyContinue
            if (!$Cargo) {
                Fail "cargo is required for -FromSource installs"
            }
            Info "building $BinName from source in $SourceDir"
            $BuildArgs = @("build", "--release", "-p", "synergy-testnet", "--bin", $BinName, "--manifest-path", (Join-Path $SourceDir "Cargo.toml"))
            if (-not $NoLocked) {
                $BuildArgs = @("build", "--release", "--locked", "-p", "synergy-testnet", "--bin", $BinName, "--manifest-path", (Join-Path $SourceDir "Cargo.toml"))
            }
            & cargo @BuildArgs
            if ($LASTEXITCODE -ne 0) {
                Fail "cargo build failed"
            }
            $SourceBinary = Join-Path $SourceDir "target\release\$BinName.exe"
            if (!(Test-Path $SourceBinary)) {
                Fail "build completed but binary is missing: $SourceBinary"
            }
        }
    } else {
        $Asset = Get-AssetName $Target
        $ReleaseUrl = Get-ReleaseUrl $Asset
        $SourceBinary = Join-Path $TempDir "$BinName.exe"
        if ($DryRun) {
            Info "would download $ReleaseUrl"
        } else {
            Info "downloading $Asset from $Repo ($Version)"
            Download-File $ReleaseUrl $SourceBinary
            if (-not $SkipSha256) {
                $Sidecar = Join-Path $TempDir "$Asset.sha256"
                Download-File "$ReleaseUrl.sha256" $Sidecar
                Verify-Sha256 $SourceBinary (Read-SidecarSha $Sidecar)
            }
        }
    }

    $Dest = Join-Path $InstallDir "$BinName.exe"
    if ($DryRun) {
        Info "would install $SourceBinary to $Dest"
        exit 0
    }

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    $InstallTmp = Join-Path $InstallDir ".$BinName.$PID.exe"
    Copy-Item -Path $SourceBinary -Destination $InstallTmp -Force
    Move-Item -Path $InstallTmp -Destination $Dest -Force

    Info "installed $Dest"
    & $Dest version
    & $Dest native-info --output compact-json | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Fail "post-install smoke check failed"
    }
    Info "post-install smoke check passed"

    if (-not $NoPathCheck) {
        $PathEntries = [Environment]::GetEnvironmentVariable("Path", "User") -split ";"
        $ProcessEntries = $env:Path -split ";"
        $InPath = ($ProcessEntries -contains $InstallDir) -or ($PathEntries -contains $InstallDir)
        if ($InPath) {
            Info "run with: $BinName native-info"
        } elseif ($AddToPath) {
            $NewUserPath = if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable("Path", "User"))) {
                $InstallDir
            } else {
                [Environment]::GetEnvironmentVariable("Path", "User") + ";$InstallDir"
            }
            [Environment]::SetEnvironmentVariable("Path", $NewUserPath, "User")
            Info "added $InstallDir to the user PATH"
            Info "restart PowerShell, then run: $BinName native-info"
        } else {
            Info "$InstallDir is not on PATH"
            Info "for this shell: `$env:Path = `"$InstallDir;`$env:Path`""
            Info "or rerun with -AddToPath"
        }
    }
} finally {
    Remove-Item -Recurse -Force $TempDir -ErrorAction SilentlyContinue
}
