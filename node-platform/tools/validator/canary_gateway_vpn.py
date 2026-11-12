#!/usr/bin/env python3
"""Coordinator-side restricted Canary gateway enrollment; never print a key in policy mode."""
import argparse
import json
from pathlib import Path
import urllib.request

NAME = "synergy-canary-rpc-gateways"
POLICY = "canary-rpc-to-validator-relay"
VALIDATORS = {"10.69.106.160", "10.69.11.219", "10.69.56.215", "10.69.184.171", "10.69.140.27"}


def prepare(api, apply=False):
    groups = api("GET", "groups")
    validators = [g for g in groups if g["name"] == "synergy-validators"]
    all_groups = [g for g in groups if g["name"] == "All"]
    if len(validators) != 1 or len(all_groups) != 1:
        raise ValueError("Selected validator groups are ambiguous")
    validator = validators[0]["id"]
    peers = api("GET", "peers")
    selected = [p for p in peers if validator in {g["id"] for g in p["groups"]}]
    if {p["ip"] for p in selected} != VALIDATORS or len(selected) != 5:
        raise ValueError("Actual validator group differs from the approved five endpoints")
    policies = api("GET", "policies")
    for p in policies:
        if not p.get("enabled"):
            continue
        for r in p["rules"]:
            if r.get("enabled") and r.get("action") == "accept":
                source = {g["id"] for g in r.get("sources", [])}
                destination = {g["id"] for g in r.get("destinations", [])}
                if all_groups[0]["id"] in source | destination:
                    raise ValueError("An active All-group policy would broaden gateway access")
    gateways = [g for g in groups if g["name"] == NAME]
    if len(gateways) > 1:
        raise ValueError("Gateway group is ambiguous")
    if not gateways:
        if not apply:
            return {"planned": True, "group_name": NAME, "policy_name": POLICY,
                    "protocol": "tcp", "destination_port": 8551}
        gateways = [api("POST", "groups", {"name": NAME, "peers": []})]
    group = gateways[0]["id"]
    for peer in peers:
        if group in {g["id"] for g in peer["groups"]}:
            memberships = {g["id"] for g in peer["groups"]}
            if peer.get("name") != "synergy-canary-rpc-99999" or memberships != {group, all_groups[0]["id"]}:
                raise ValueError("Gateway group contains an unexpected peer or broader memberships")
    expected = dict(name=POLICY, description="Canary APQE relay only; no validator P2P or plain RPC",
                    enabled=True, rules=[dict(name=POLICY, enabled=True, action="accept",
                    bidirectional=False, protocol="tcp", sources=[group], destinations=[validator],
                    ports=["8551"])])
    matches = [p for p in policies if p["name"] == POLICY]
    if len(matches) > 1:
        raise ValueError("Gateway policy is ambiguous")
    for p in policies:
        for r in p.get("rules", []):
            ids = {g["id"] for g in r.get("sources", []) + r.get("destinations", [])}
            if p.get("enabled") and r.get("enabled") and group in ids and p["name"] != POLICY:
                raise ValueError("Another enabled policy widens gateway access")
    if not matches:
        if apply:
            matches = [api("POST", "policies", expected)]
        else:
            return {"planned": True, "group_id": group, "policy": expected}
    actual = matches[0]
    if actual.get("enabled") is not True or len(actual["rules"]) != 1:
        raise ValueError("Existing gateway policy differs")
    rule = actual["rules"][0]
    for key in ("enabled", "action", "bidirectional", "protocol", "ports"):
        if rule.get(key) != expected["rules"][0][key]:
            raise ValueError("Existing gateway rule differs: " + key)
    if ({g["id"] for g in rule["sources"]} != {group}
            or {g["id"] for g in rule["destinations"]} != {validator}
            or rule.get("port_ranges")):
        raise ValueError("Existing gateway endpoint or port scope differs")
    return {"group_id": group, "policy_id": actual["id"], "destination_port": 8551,
            "validator_count": 5, "policy_verified": True}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("command", choices=("plan", "policy", "key"))
    p.add_argument("--token-path", type=Path, required=True)
    args = p.parse_args()
    info = args.token_path.lstat()
    if args.token_path.is_symlink() or info.st_mode & 0o077:
        raise ValueError("Owner-only coordinator credential required")
    token = args.token_path.read_text().strip()
    def api(method, path, value=None):
        request = urllib.request.Request("http://127.0.0.1:8080/api/" + path,
            json.dumps(value).encode() if value is not None else None,
            {"Authorization": "Token " + token, "Content-Type": "application/json"}, method=method)
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.load(response)
    result = prepare(api, args.command == "policy")
    if args.command == "key":
        if not result.get("policy_verified"):
            raise ValueError("Configure and qualify the restricted policy first")
        key = api("POST", "setup-keys", {"name": "canary-rpc-99999-one-off",
            "type": "one-off", "expires_in": 86400, "usage_limit": 1,
            "auto_groups": [result["group_id"]], "ephemeral": False})
        # This mode must be piped directly into the canonical gateway provisioner.
        # Nothing is stored locally and the management credential stays on its host.
        result = {"setup_key": key["key"], "setup_key_id": str(key["id"]),
                  "management_url": "https://vpn-coordinator.synergy-network.io:443",
                  "hostname": "synergy-canary-rpc-99999",
                  "required_peer_ips": sorted(VALIDATORS)}
    print(json.dumps(result))


if __name__ == "__main__":
    main()
