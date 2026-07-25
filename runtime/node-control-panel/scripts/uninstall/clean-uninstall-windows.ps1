param(
  [switch]$Force
)

$ErrorActionPreference = "Continue"

function Write-Log {
  param([string]$Message)
  Write-Host "[clean-uninstall-windows] $Message"
}

function Write-Warn {
  param([string]$Message)
  Write-Warning "[clean-uninstall-windows] $Message"
}

function Test-Admin {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Confirm-DestructiveAction {
  Write-Host "This will permanently delete:"
  Write-Host "  - Synergy Node Control Panel installs and app data"
  Write-Host "  - local validator/node workspaces under $env:USERPROFILE\.synergy\testnet"
  Write-Host "  - monitor workspaces under $env:USERPROFILE\.synergy-node-control-panel"
  Write-Host "  - startup agents, Windows services, firewall rules, and shortcuts"
  Write-Host "  - validator/node runtimes under C:\Synergy\Testnet"
  Write-Host ""
  Write-Host "Bootnode and seed-server directories are intentionally preserved."

  if ($Force) {
    return
  }

  $confirm = Read-Host "Type REMOVE to continue"
  if ($confirm -ne "REMOVE") {
    Write-Log "Cancelled."
    exit 0
  }
}

function Remove-PathSafe {
  param([string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) { return }
  if (Test-Path -LiteralPath $Path) {
    Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
    Write-Log "Removed $Path"
  }
}

function Remove-WildcardSafe {
  param([string]$Pattern)
  if ([string]::IsNullOrWhiteSpace($Pattern)) { return }
  Get-ChildItem -Path $Pattern -Force -ErrorAction SilentlyContinue | ForEach-Object {
    Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
    Write-Log "Removed $($_.FullName)"
  }
}

function Remove-EmptyDirectorySafe {
  param([string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) { return }
  if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }
  if ((Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue | Measure-Object).Count -eq 0) {
    Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    Write-Log "Removed empty directory $Path"
  }
}

function Stop-KnownProcesses {
  $names = @(
    "synergy-testnet-agent",
    "control-service",
    "Synergy Node Control Panel"
  )

  foreach ($name in $names) {
    Stop-Process -Name $name -Force -ErrorAction SilentlyContinue
  }

  Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
    Where-Object {
      $_.CommandLine -match "synergy-testnet-agent|control-service|Synergy Node Control Panel|\\.synergy\\testnet\\nodes\\|\\Synergy\\Testnet\\node-|\\Synergy\\Testnet\\validator"
    } |
    ForEach-Object {
      Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
    }
}

function Remove-WindowsServices {
  Get-Service -Name "synergy-testnet-agent" -ErrorAction SilentlyContinue | ForEach-Object {
    Stop-Service -Name $_.Name -Force -ErrorAction SilentlyContinue
    sc.exe delete $_.Name *> $null
    Write-Log "Removed Windows service $($_.Name)"
  }
}

function Run-Uninstallers {
  $uninstallers = @(
    "$env:LOCALAPPDATA\Programs\Synergy Node Control Panel\Uninstall Synergy Node Control Panel.exe",
    "$env:LOCALAPPDATA\Programs\synergy-node-control-panel\Uninstall Synergy Node Control Panel.exe",
    "$env:LOCALAPPDATA\Programs\io.synergy-network.node-control-panel\Uninstall Synergy Node Control Panel.exe",
    "$env:ProgramFiles\Synergy Node Control Panel\Uninstall Synergy Node Control Panel.exe",
    "$env:ProgramFiles(x86)\Synergy Node Control Panel\Uninstall Synergy Node Control Panel.exe"
  )

  foreach ($uninstaller in $uninstallers) {
    if (Test-Path -LiteralPath $uninstaller) {
      try {
        & $uninstaller /S *> $null
        Write-Log "Ran uninstaller $uninstaller"
      } catch {
        Write-Warn "Uninstaller failed: $uninstaller"
      }
    }
  }
}

function Remove-FirewallRules {
  Get-NetFirewallRule -DisplayName "Synergy-*" -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_.DisplayName -match '^Synergy-(?i:bootnode|seed)') {
      return
    }
    Remove-NetFirewallRule -Name $_.Name -ErrorAction SilentlyContinue
    Write-Log "Removed firewall rule $($_.DisplayName)"
  }
}

function Remove-RegistryRemnants {
  $roots = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
  )

  foreach ($root in $roots) {
    Get-ChildItem -Path $root -ErrorAction SilentlyContinue | ForEach-Object {
      try {
        $props = Get-ItemProperty -Path $_.PSPath -ErrorAction Stop
        $display = "$($props.DisplayName) $($props.Publisher) $($props.PSChildName)"
        if ($display -match "Synergy Node Control Panel|synergy-node-control-panel|io\.synergy-network\.node-control-panel|com\.synergy\.node-monitor") {
          Remove-Item -Path $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
          Write-Log "Removed uninstall registry key $($_.PSChildName)"
        }
      } catch {
      }
    }
  }
}

function Remove-ShortcutsAndStartup {
  $startupLink = Join-Path ([Environment]::GetFolderPath("Startup")) "Synergy Testnet Agent.cmd"
  Remove-PathSafe $startupLink

  $wildcards = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Synergy Node Control Panel*",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Synergy Node Control Panel*",
    "$env:USERPROFILE\Desktop\Synergy Node Control Panel*.lnk",
    "$env:PUBLIC\Desktop\Synergy Node Control Panel*.lnk"
  )

  foreach ($pattern in $wildcards) {
    Remove-WildcardSafe $pattern
  }
}

function Remove-FilesAndDirectories {
  $paths = @(
    "$env:USERPROFILE\.synergy-node-control-panel",
    "$env:USERPROFILE\.synergy-testnet-control-panel",
    "$env:USERPROFILE\.synergy-node-monitor",
    "$env:USERPROFILE\.synergy\node",
    "$env:USERPROFILE\.synergy\testnet\nodes",
    "$env:USERPROFILE\.synergy\testnet\network",
    "$env:USERPROFILE\.synergy\testnet\wallets",
    "$env:APPDATA\synergy-node-control-panel",
    "$env:APPDATA\Synergy Node Control Panel",
    "$env:APPDATA\com.synergy.node-monitor",
    "$env:APPDATA\io.synergy-network.node-control-panel",
    "$env:LOCALAPPDATA\synergy-node-control-panel",
    "$env:LOCALAPPDATA\Synergy Node Control Panel",
    "$env:LOCALAPPDATA\com.synergy.node-monitor",
    "$env:LOCALAPPDATA\io.synergy-network.node-control-panel",
    "$env:LOCALAPPDATA\synergy-node-control-panel-updater",
    "$env:LOCALAPPDATA\Synergy Node Control Panel-updater",
    "$env:LOCALAPPDATA\io.synergy-network.node-control-panel-updater",
    "$env:LOCALAPPDATA\Programs\Synergy Node Control Panel",
    "$env:LOCALAPPDATA\Programs\synergy-node-control-panel",
    "$env:LOCALAPPDATA\Programs\io.synergy-network.node-control-panel",
    "$env:ProgramFiles\Synergy Node Control Panel",
    "$env:ProgramFiles(x86)\Synergy Node Control Panel",
    "$env:USERPROFILE\synergy-testnet-agent.log"
  )

  foreach ($path in $paths) {
    Remove-PathSafe $path
  }

  $selectivePatterns = @(
    "C:\Synergy\Testnet\node-*",
    "C:\Synergy\Testnet\validator*"
  )

  foreach ($pattern in $selectivePatterns) {
    Remove-WildcardSafe $pattern
  }

  Remove-EmptyDirectorySafe "$env:USERPROFILE\.synergy\testnet\ceremony\imports"
  Remove-EmptyDirectorySafe "$env:USERPROFILE\.synergy\testnet\ceremony"
  Remove-EmptyDirectorySafe "$env:USERPROFILE\.synergy\testnet"
  Remove-EmptyDirectorySafe "$env:USERPROFILE\.synergy"
  Remove-EmptyDirectorySafe "C:\Synergy\Testnet"
  Remove-EmptyDirectorySafe "C:\Synergy"
}

Confirm-DestructiveAction

if (-not (Test-Admin)) {
  Write-Warn "Run this script as Administrator to remove system services, firewall rules, and machine-wide installs."
}

Stop-KnownProcesses
Remove-WindowsServices
Run-Uninstallers
Remove-FirewallRules
Remove-RegistryRemnants
Remove-ShortcutsAndStartup
Remove-FilesAndDirectories

Write-Log "Clean uninstall complete."
