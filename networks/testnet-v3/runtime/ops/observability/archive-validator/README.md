# Archive Validator Observability Handoff

This folder is the complete file handoff for adding Archive Validator to the observer-hosted Grafana and Prometheus stack.

Move these files to the Archive Validator machine:

- `archive-validator-observability.env`
- `install-archive-observability.sh`
- `ARCHIVE_VALIDATOR_TERMINAL_COMMANDS.md`
- `README.md`

The installer is credential-free and macOS-specific. Archive Validator is not on the VPN, so Prometheus scrapes its public IP `73.79.66.255`. The installer patches the macOS archive node config so runtime metrics bind on `0.0.0.0:6030`, installs/configures Homebrew `node_exporter` through launchd on `0.0.0.0:9100`, kickstarts the archive validator launchd service when present, and prints a sanitized `spreadsheet_row_used=true` proof line.

Network exposure is still an operator step on the Mac/router/firewall: allow or forward public TCP `6030` and `9100` from Observer public IP `209.145.50.9` to the Archive Validator Mac. qRPC `5640` is optional for Grafana reachability checks.

Observer-side Prometheus/Grafana source files are in:

- `ops/observability/prometheus.observer.yml`
- `ops/observability/grafana/*.json`

Archive Validator is labeled as `archive_validator` / `archive-validator` and is not included as an active voting validator in consensus or PoSy scoring panels.
