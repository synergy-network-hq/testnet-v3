# Synergy AIVM Operator Playbook

## Overview
This playbook guides node operators on deploying, maintaining, and monitoring Synergy AIVM nodes and GPU workers.

## 1. Node Setup
1. Install Rust, Cargo, and system dependencies.
2. Clone the `synergy-aivm` repository.
3. Deploy provider agent node via:
   ```bash
   cd providers/provider-operator/deploy
   ./node-setup.sh
   ```
4. Deploy Kubernetes resources if applicable:
   ```bash
   kubectl apply -f k8s-deployment.yaml
   ```

## 2. GPU Worker Setup
1. Create a Python virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
2. Configure *worker_config.yaml* with node addresses and model paths.
3. Start the worker service:
   ```bash
   python worker_service.py
   ```

## 3. Monitoring & Logging
- Check logs/ for node output.
- Integrate with Prometheus/Grafana dashboards.
- Monitor attestation health for TEEs.

## 4. Maintenance
- Apply Rust and Python runtime updates regularly.
- Rotate keys for node identity and worker attestation.
- Follow governance updates for protocol changes.

## 5. Troubleshooting
- Node not syncing → check RPC endpoints and firewall rules.
- Worker failing inference → validate model manifest and ONNX runtime.
- Attestation errors → verify SGX driver and enclave setup.

---

*Version 1.0 – 2025-09-07*

---
