#!/bin/bash
# examples/multipath_demo.sh

set -e

# Compile the benchmark
echo "Compiling data multipath benchmark..."
make examples/data_multipath_benchmark gencerts

# Run the benchmark in an unshared user/network namespace
echo "Entering isolated namespace for multipath setup..."
unshare -Urn bash -c '
    set -e
    
    # Enable loopback
    ip link set lo up
    
    # Set up classful prio qdisc on loopback to simulate delays per IP subnet
    tc qdisc add dev lo root handle 1: prio bands 4
    
    # Class 1:1 -> Cellular (40ms delay per direction / 80ms same-link RTT)
    tc qdisc add dev lo parent 1:1 handle 10: netem delay 40ms
    tc filter add dev lo protocol ip parent 1:0 prio 1 u32 match ip dst 10.0.1.0/24 flowid 1:1
    
    # Path 0 (Cellular)
    ip link add veth1 type veth peer name veth1_peer
    ip addr add 10.0.1.1/24 dev veth1
    ip addr add 10.0.1.2/24 dev veth1_peer
    ip link set veth1 up
    ip link set veth1_peer up
    
    echo ""
    echo "====================================================="
    echo "  TEST 1: Dynamic Multipath Mode (data stream)"
    echo "====================================================="
    echo "Link profiles shape delay/loss only; bandwidth is uncapped."
    echo "Path 0: Cellular (40ms per direction / 80ms same-link RTT, no injected loss)"
    # We pass all potential remote IPs so the client knows them.
    # We only pass the first local IPs to start, the rest will be dynamically discovered.
    ./examples/data_multipath_benchmark \
        --server-bind 10.0.1.1 \
        --server-interface veth1 veth2 veth3 veth4 \
        --client-bind 10.0.1.2 \
        --client-interface veth1_peer veth2_peer veth3_peer veth4_peer \
        --client-remote 10.0.1.1 10.0.2.1 10.0.3.1 10.0.4.1 \
        --expect-preferred-interface veth4 &
    BENCH_PID=$!
    
    sleep 2
    
    # Path 1 (Wi-Fi)
    echo "Dynamically bringing up Path 1: Wi-Fi (40ms per direction / 80ms same-link RTT, GE: p=5%, r=50%, bad-loss=100%, good-loss=0.5%)"
    # GE parameters are state-transition and conditional-loss probabilities,
    # not a flat 5% packet-loss rate.
    tc qdisc add dev lo parent 1:2 handle 20: netem delay 40ms loss gemodel 5% 50% 100% 0.5%
    tc filter add dev lo protocol ip parent 1:0 prio 1 u32 match ip dst 10.0.2.0/24 flowid 1:2
    
    ip link add veth2 type veth peer name veth2_peer
    ip addr add 10.0.2.1/24 dev veth2
    ip addr add 10.0.2.2/24 dev veth2_peer
    ip link set veth2 up
    ip link set veth2_peer up
    
    sleep 3
    
    # Path 2 (Satcom)
    echo "Dynamically bringing up Path 2: Satcom (70ms per direction / 140ms same-link RTT, 2% loss)"
    # Class 1:3 -> Satcom (70ms delay / 140ms RTT, 2% loss)
    tc qdisc add dev lo parent 1:3 handle 30: netem delay 70ms loss 2%
    tc filter add dev lo protocol ip parent 1:0 prio 1 u32 match ip dst 10.0.3.0/24 flowid 1:3
    
    ip link add veth3 type veth peer name veth3_peer
    ip addr add 10.0.3.1/24 dev veth3
    ip addr add 10.0.3.2/24 dev veth3_peer
    ip link set veth3 up
    ip link set veth3_peer up
    
    sleep 3
    
    # Path 3 (Ethernet)
    echo "Dynamically bringing up Path 3: Ethernet (2ms per direction / 4ms same-link RTT, 0.1% loss)"
    # Class 1:4 -> Ethernet (2ms delay / 4ms RTT, 0.1% loss)
    tc qdisc add dev lo parent 1:4 handle 40: netem delay 2ms loss 0.1%
    tc filter add dev lo protocol ip parent 1:0 prio 1 u32 match ip dst 10.0.4.0/24 flowid 1:4
    
    ip link add veth4 type veth peer name veth4_peer
    ip addr add 10.0.4.1/24 dev veth4
    ip addr add 10.0.4.2/24 dev veth4_peer
    ip link set veth4 up
    ip link set veth4_peer up
    
    wait $BENCH_PID
    echo ""
'
