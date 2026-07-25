Synergy Testnet Installer
================================

Node Slot: GenVal-01
Role Group: consensus
Role: validator
Node Type: validator

Quick Start (Linux/macOS)
-------------------------
1) Copy this entire folder to the target machine.
2) Run:
   ./install_and_start.sh
3) Verify:
   ./nodectl.sh status
   ./nodectl.sh logs --follow

Quick Start (Windows)
---------------------
1) Copy this entire folder to the target machine.
2) Run in PowerShell:
   powershell -ExecutionPolicy Bypass -File .\install_and_start.ps1
3) Verify:
   powershell -ExecutionPolicy Bypass -File .\nodectl.ps1 status
   powershell -ExecutionPolicy Bypass -File .\nodectl.ps1 logs -Follow

Notes
-----
- The installer includes Linux x86_64, macOS arm64, and Windows x86_64 binaries.
- Linux firewall automation supports ufw, firewalld, and iptables.
- Windows firewall automation prompts for elevation when needed and otherwise prints the required TCP ports.
- This folder is self-contained for this node instance.
- Public DNS should resolve only to approved public hosts.
- See BINARY_STATUS.txt for bundled binary paths and SHA-256 checksums.
