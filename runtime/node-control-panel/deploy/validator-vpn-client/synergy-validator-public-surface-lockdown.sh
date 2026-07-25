#!/usr/bin/env bash
set -euo pipefail

public_interface="$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i=="dev") {print $(i+1); exit}}')"
[[ -n "$public_interface" ]] || {
  echo "Could not identify the validator public interface." >&2
  exit 1
}

delete_all() {
  local table_command="$1"
  shift
  while "$table_command" -C "$@" 2>/dev/null; do
    "$table_command" -D "$@"
  done
}

# Remove retired direct-public and legacy validator VPN exceptions. The exact
# host rule is retained for older deployments; the range cleanup handles any
# broader legacy accept/drop rule left by the former static mesh.
delete_all iptables INPUT -s 157.173.192.45/32 -p tcp --dport 5622 -j ACCEPT
delete_all iptables OUTPUT -d 157.173.192.45/32 -p tcp --sport 5622 -j ACCEPT
delete_all iptables INPUT -s 10.69.0.220/32 -p tcp --dport 5622 -j ACCEPT
delete_all iptables OUTPUT -d 10.69.0.220/32 -p tcp --sport 5622 -j ACCEPT
delete_all iptables INPUT -s 10.69.0.220/32 -j DROP
delete_all iptables OUTPUT -d 10.69.0.220/32 -j DROP
for chain in INPUT OUTPUT FORWARD; do
  delete_all iptables "${chain}" -s 10.69.0.0/16 -j ACCEPT
  delete_all iptables "${chain}" -d 10.69.0.0/16 -j ACCEPT
  delete_all iptables "${chain}" -s 10.69.0.0/16 -j DROP
  delete_all iptables "${chain}" -d 10.69.0.0/16 -j DROP
done

# Relayers are canonical VPN peers and must reach validator P2P over sy-vpn.
delete_all iptables INPUT -s 10.70.20.0/24 -i sy-vpn -p tcp --dport 5622 -j DROP
delete_all iptables OUTPUT -d 10.70.20.0/24 -o sy-vpn -p tcp --dport 5622 -j DROP

tcp_ports="5622,5640,5660,5680,6030,9100"
iptables -C INPUT -i "$public_interface" -p tcp -m multiport --dports "$tcp_ports" -j DROP 2>/dev/null \
  || iptables -I INPUT 1 -i "$public_interface" -p tcp -m multiport --dports "$tcp_ports" -j DROP
iptables -C INPUT -i "$public_interface" -p udp --dport 5680 -j DROP 2>/dev/null \
  || iptables -I INPUT 1 -i "$public_interface" -p udp --dport 5680 -j DROP
iptables -C OUTPUT -o "$public_interface" -p tcp --dport 5622 -j DROP 2>/dev/null \
  || iptables -I OUTPUT 1 -o "$public_interface" -p tcp --dport 5622 -j DROP
iptables -C OUTPUT -o "$public_interface" -p tcp -m multiport --sports "$tcp_ports" -j DROP 2>/dev/null \
  || iptables -I OUTPUT 1 -o "$public_interface" -p tcp -m multiport --sports "$tcp_ports" -j DROP

if command -v ip6tables >/dev/null 2>&1; then
  ip6tables -C INPUT -i "$public_interface" -p tcp -m multiport --dports "$tcp_ports" -j DROP 2>/dev/null \
    || ip6tables -I INPUT 1 -i "$public_interface" -p tcp -m multiport --dports "$tcp_ports" -j DROP
  ip6tables -C INPUT -i "$public_interface" -p udp --dport 5680 -j DROP 2>/dev/null \
    || ip6tables -I INPUT 1 -i "$public_interface" -p udp --dport 5680 -j DROP
  ip6tables -C OUTPUT -o "$public_interface" -p tcp --dport 5622 -j DROP 2>/dev/null \
    || ip6tables -I OUTPUT 1 -o "$public_interface" -p tcp --dport 5622 -j DROP
  ip6tables -C OUTPUT -o "$public_interface" -p tcp -m multiport --sports "$tcp_ports" -j DROP 2>/dev/null \
    || ip6tables -I OUTPUT 1 -o "$public_interface" -p tcp -m multiport --sports "$tcp_ports" -j DROP
fi
