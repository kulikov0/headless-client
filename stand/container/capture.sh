#!/bin/bash
set -euo pipefail

out=$1
timeout_secs=$2
shift 2

roles=()
declare -A commands
for spec in "$@"; do
  name=${spec%%=*}
  roles+=("$name")
  commands[$name]=${spec#*=}
done

if [ ${#roles[@]} -eq 0 ]; then
  echo "capture: no roles given" >&2
  exit 1
fi

mkdir -p "$out" /stand/keylog
rm -f /stand/keylog/*.log

nameservers=$(grep '^nameserver' /etc/resolv.conf | grep -v ' 127\.' || true)
[ -n "$nameservers" ] || nameservers="nameserver 1.1.1.1"

declare -A addresses
subnet=0
for role in "${roles[@]}"; do
  subnet=$((subnet + 1))
  gateway="10.201.$subnet.1"
  address="10.201.$subnet.2"
  addresses[$role]=$address

  ip netns add "$role"
  ip link add "veth-$role" type veth peer name "peer-$role"
  ip link set "peer-$role" netns "$role"
  ip addr add "$gateway/30" dev "veth-$role"
  ip link set "veth-$role" up
  ip netns exec "$role" ip link set "peer-$role" name eth0
  ip netns exec "$role" ip link set lo up
  ip netns exec "$role" ip addr add "$address/30" dev eth0
  ip netns exec "$role" ip link set eth0 up
  ip netns exec "$role" ip route add default via "$gateway"
  iptables -t nat -A POSTROUTING -s "$address/32" -j MASQUERADE

  mkdir -p "/etc/netns/$role"
  printf '%s\n' "$nameservers" > "/etc/netns/$role/resolv.conf"
done

teardown() {
  set +e
  for role in "${roles[@]}"; do
    iptables -t nat -D POSTROUTING -s "${addresses[$role]}/32" -j MASQUERADE 2>/dev/null
    ip netns delete "$role" 2>/dev/null
    rm -rf "/etc/netns/$role"
  done
}
trap teardown EXIT

captures=()
for role in "${roles[@]}"; do
  tcpdump -i "veth-$role" -s 0 -U -w "$out/$role.pcap" >/dev/null 2>"$out/$role.tcpdump.log" &
  captures+=("$!")
  ip netns exec "$role" tcpdump -i lo -s 0 -U -w "$out/$role.loopback.pcap" >/dev/null 2>"$out/$role.loopback.tcpdump.log" &
  captures+=("$!")
done
sleep 1

runners=()
for role in "${roles[@]}"; do
  limit=()
  [ "$timeout_secs" -gt 0 ] && limit=(timeout --signal=INT "${timeout_secs}s")
  SSLKEYLOGFILE="/stand/keylog/$role.log" \
    ip netns exec "$role" "${limit[@]}" bash -lc "${commands[$role]}" >"$out/$role.stdout.log" 2>&1 &
  runners+=("$!")
done

stop() {
  for pid in "${runners[@]}"; do
    kill -INT "$pid" 2>/dev/null || true
  done
}
trap 'stop' TERM INT

for pid in "${runners[@]}"; do
  wait "$pid" || true
done

sleep 1
for pid in "${captures[@]}"; do
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
done

for role in "${roles[@]}"; do
  touch "/stand/keylog/$role.log"
  cp "/stand/keylog/$role.log" "$out/$role.keys"
done

roles_json={}
for role in "${roles[@]}"; do
  roles_json=$(jq --arg name "$role" --arg address "${addresses[$role]}" --arg command "${commands[$role]}" \
    '.[$name] = {address: $address, command: $command}' <<<"$roles_json")
done

jq -n \
  --arg capturedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg chromium "$(chromium --version)" \
  --arg chromiumPackage "$(dpkg-query -W -f='${Version}' chromium)" \
  --arg tshark "$(tshark --version | head -1)" \
  --arg tcpdump "$(tcpdump --version 2>&1 | head -1)" \
  --arg kernel "$(uname -sr)" \
  --argjson roles "$roles_json" \
  '{$capturedAt, $chromium, $chromiumPackage, $tshark, $tcpdump, $kernel, $roles}' \
  > "$out/manifest.json"
