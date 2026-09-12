#!/usr/bin/env bash

set -euo pipefail

if [[ $(id -u) -ne 0 ]]; then
  if ! command -v unshare >/dev/null 2>&1; then
    echo "check-flexicast-netns needs root/CAP_NET_ADMIN or unshare." >&2
    exit 77
  fi
  exec unshare --user --map-root-user --net "$0" "$@"
fi

repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
test_binary="$repo_root/t/00util/test_flexicast_transport"
log_dir=$(mktemp -d /tmp/qlinq-flexicast-netns.XXXXXX)
holder_pids=""
test_pids=""

show_logs() {
  for log in "$log_dir"/*.log; do
    if [[ -f "$log" ]]; then
      echo "--- ${log##*/} ---" >&2
      sed -n '1,160p' "$log" >&2
    fi
  done
}

cleanup() {
  for pid in $test_pids $holder_pids; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  rm -f "$log_dir"/*.log
  rmdir "$log_dir" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

for command in ip nsenter unshare timeout; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "check-flexicast-netns requires $command." >&2
    exit 77
  fi
done
if [[ ! -x "$test_binary" ]]; then
  echo "build $test_binary before running this harness." >&2
  exit 1
fi

start_namespace() {
  unshare --net -- sleep infinity &
  namespace_pid=$!
  holder_pids="$holder_pids $namespace_pid"
}

start_namespace
switch_ns=$namespace_pid
start_namespace
source_ns=$namespace_pid
start_namespace
receiver_a_ns=$namespace_pid
start_namespace
receiver_b_ns=$namespace_pid
start_namespace
attacker_ns=$namespace_pid
sleep 0.1
for namespace_pid in $holder_pids; do
  kill -0 "$namespace_pid"
  nsenter -t "$namespace_pid" -n -- ip link set lo up
done

nsenter -t "$switch_ns" -n -- ip link add br0 type bridge
nsenter -t "$switch_ns" -n -- ip link set br0 type bridge mcast_snooping 0
nsenter -t "$switch_ns" -n -- ip link set br0 up

attach_namespace() {
  local namespace_pid=$1
  local prefix=$2
  local switch_port=$3
  ip link add "${prefix}0" type veth peer name "${prefix}1"
  ip link set "${prefix}0" netns "$namespace_pid"
  ip link set "${prefix}1" netns "$switch_ns"
  nsenter -t "$namespace_pid" -n -- ip link set "${prefix}0" name eth0
  nsenter -t "$namespace_pid" -n -- ip link set eth0 up
  nsenter -t "$switch_ns" -n -- ip link set "${prefix}1" name "$switch_port"
  nsenter -t "$switch_ns" -n -- ip link set "$switch_port" master br0
  nsenter -t "$switch_ns" -n -- ip link set "$switch_port" up
}

attach_namespace "$source_ns" qfs src0
attach_namespace "$receiver_a_ns" qfa recv0
attach_namespace "$receiver_b_ns" qfb recv1
attach_namespace "$attacker_ns" qfx bad0

configure_endpoint() {
  local namespace_pid=$1
  local v4=$2
  local v6=$3
  nsenter -t "$namespace_pid" -n -- ip address add "$v4/24" dev eth0
  nsenter -t "$namespace_pid" -n -- \
    ip -6 address add "$v6/64" dev eth0 nodad
  nsenter -t "$namespace_pid" -n -- \
    ip route add 224.0.0.0/4 dev eth0
  nsenter -t "$namespace_pid" -n -- \
    ip -6 route add ff00::/8 dev eth0
}

configure_endpoint "$source_ns" 10.241.0.1 fd42:514c:494e:5100::1
configure_endpoint "$receiver_a_ns" 10.241.0.2 fd42:514c:494e:5100::2
configure_endpoint "$receiver_b_ns" 10.241.0.3 fd42:514c:494e:5100::3
configure_endpoint "$attacker_ns" 10.241.0.99 fd42:514c:494e:5100::99

run_family() {
  local family=$1
  local source=$2
  local receiver_a=$3
  local receiver_b=$4
  local attacker=$5
  local group=$6
  local control_port=$7
  local group_port=$8
  local label="v$family"

  nsenter -t "$source_ns" -n -- timeout 20 "$test_binary" --netns-server \
    "$family" "$source" "$group" "$control_port" "$group_port" 2 \
    >"$log_dir/source-$label.log" 2>&1 &
  local source_pid=$!
  test_pids="$test_pids $source_pid"
  nsenter -t "$receiver_a_ns" -n -- timeout 20 "$test_binary" \
    --netns-client "$family" "$receiver_a" "$source" "$control_port" \
    >"$log_dir/receiver-a-$label.log" 2>&1 &
  local a_pid=$!
  test_pids="$test_pids $a_pid"
  nsenter -t "$receiver_b_ns" -n -- timeout 20 "$test_binary" \
    --netns-client "$family" "$receiver_b" "$source" "$control_port" \
    >"$log_dir/receiver-b-$label.log" 2>&1 &
  local b_pid=$!
  test_pids="$test_pids $b_pid"

  sleep 1
  nsenter -t "$attacker_ns" -n -- timeout 8 "$test_binary" --netns-noise \
    "$family" "$attacker" "$group" "$group_port" 200 \
    >"$log_dir/noise-$label.log" 2>&1 &
  local noise_pid=$!
  test_pids="$test_pids $noise_pid"

  local result=0
  wait "$noise_pid" || result=1
  wait "$a_pid" || result=1
  wait "$b_pid" || result=1
  wait "$source_pid" || result=1
  test_pids=""
  if [[ $result -ne 0 ]]; then
    show_logs
    return 1
  fi
  grep -q "FLEXICAST NETNS IPV${family} SOURCE OK" \
    "$log_dir/source-$label.log" || result=1
  grep -q "FLEXICAST NETNS IPV${family} RECEIVER OK" \
    "$log_dir/receiver-a-$label.log" || result=1
  grep -q "FLEXICAST NETNS IPV${family} RECEIVER OK" \
    "$log_dir/receiver-b-$label.log" || result=1
  if [[ $result -ne 0 ]]; then
    show_logs
    return 1
  fi
  echo "Flexicast IPv$family SSM namespace test passed"
}

run_family 4 10.241.0.1 10.241.0.2 10.241.0.3 10.241.0.99 \
  232.42.42.61 12061 12062
run_family 6 fd42:514c:494e:5100::1 fd42:514c:494e:5100::2 \
  fd42:514c:494e:5100::3 fd42:514c:494e:5100::99 ff3e::4242:61 12063 12064

echo "===FLEXICAST NETNS SSM OK==="
