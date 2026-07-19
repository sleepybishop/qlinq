#!/bin/bash
# examples/tun_demo.sh

set -e

# Ensure workspace-local directories exist for logs
mkdir -p logs

# 1. Compile all required daemons
echo "Compiling bishlink host, client, and tun daemons..."
make bishlinkd bishlink-tund

# 2. Run the comparison benchmark inside an unshared user/network/mount namespace
echo "Launching virtual tunnel benchmark inside isolated namespace stack..."
unshare -Urnm bash -c '
    set -e

    # Mount tmpfs over /run to support nested ip netns without host root
    mount -t tmpfs tmpfs /run
    mkdir -p /run/netns

    # Create isolated namespaces for host and client
    ip netns add ns_host
    ip netns add ns_client

    # Create veth pair to connect host and client namespaces
    ip link add veth_host type veth peer name veth_client
    ip link set veth_host netns ns_host
    ip link set veth_client netns ns_client

    # Configure the host-side namespace interface
    ip netns exec ns_host ip link set lo up
    ip netns exec ns_host ip addr add 192.168.1.1/24 dev veth_host
    ip netns exec ns_host ip link set veth_host up

    # Configure the client-side namespace interface
    ip netns exec ns_client ip link set lo up
    ip netns exec ns_client ip addr add 192.168.1.2/24 dev veth_client
    ip netns exec ns_client ip link set veth_client up

    # Apply Gilbert-Elliot burst loss on the transport link (veth interfaces) using Traffic Control
    echo "Applying realistic burst loss (p=5%, r=50%, bad=100%, good=0.5%) to transport links..."
    ip netns exec ns_host tc qdisc add dev veth_host root netem loss gemodel 5% 50% 100% 0.5%
    ip netns exec ns_client tc qdisc add dev veth_client root netem loss gemodel 5% 50% 100% 0.5%

    # Verify they can reach each other directly over the veth link
    ip netns exec ns_host ping -c 1 192.168.1.2 > /dev/null

    # Generate 16MB file with random contents
    TEST_DIR=$(pwd)/logs/test_transfer
    mkdir -p "$TEST_DIR"
    echo "Generating 16MB random test file..."
    dd if=/dev/urandom of="$TEST_DIR/test_16mb.bin" bs=1M count=16 2>/dev/null
    SOURCE_HASH=$(sha256sum "$TEST_DIR/test_16mb.bin" | cut -d" " -f1)
    echo "Source SHA256: $SOURCE_HASH"
    echo ""

    # ========================================================
    # RUN 1: RaptorQ FEC Datagram Mode
    # ========================================================
    echo "=== RUN 1: RaptorQ FEC Datagram Mode ==="
    ip netns exec ns_host ./bishlinkd --listen 8888 --bind 192.168.1.1 --socket bishlink-data --track tund/tun-client > logs/host_fec.log 2>&1 &
    PID_HOST=$!
    ip netns exec ns_client ./bishlinkd --peer 192.168.1.1:8888 --socket bishlink-data-client --track tund/tun-host > logs/client_fec.log 2>&1 &
    PID_CLIENT=$!
    sleep 2

    ip netns exec ns_host ./bishlink-tund --socket bishlink-data -i tun-host -a 10.8.0.1/24 --track tund/tun-host > logs/tund_host_fec.log 2>&1 &
    PID_TUND_HOST=$!
    ip netns exec ns_client ./bishlink-tund --socket bishlink-data-client -i tun-client -a 10.8.0.2/24 --track tund/tun-client > logs/tund_client_fec.log 2>&1 &
    PID_TUND_CLIENT=$!
    sleep 2

    # Measure latency over FEC tunnel before transfer
    echo "Measuring RTT latency over FEC tunnel..."
    LATENCY_FEC=$(ip netns exec ns_host ping -c 5 -W 1 10.8.0.2 | python3 -c "
import re, sys
m = re.search(r\"rtt min/avg/max/mdev = ([0-9.]+)/([0-9.]+)/([0-9.]+)\", sys.stdin.read())
print(m.group(2) + \" ms\" if m else \"N/A\")
")
    echo "FEC Latency: $LATENCY_FEC"

    ip netns exec ns_host python3 -m http.server --directory "$TEST_DIR" --bind 10.8.0.1 8080 > /dev/null 2>&1 &
    PID_WEBSERVER=$!
    sleep 1

    echo "Downloading 16MB file over FEC tunnel..."
    START_FEC=$(python3 -c "import time; print(time.time())")
    ip netns exec ns_client curl -s -o "$TEST_DIR/received_fec.bin" http://10.8.0.1:8080/test_16mb.bin
    END_FEC=$(python3 -c "import time; print(time.time())")
    DURATION_FEC=$(python3 -c "print(round($END_FEC - $START_FEC, 3))")
    THROUGHPUT_FEC=$(python3 -c "print(round(16.0 / $DURATION_FEC, 3))")
    echo "FEC Datagram Duration: ${DURATION_FEC}s (Throughput: ${THROUGHPUT_FEC} MB/s)"

    FEC_HASH=$(sha256sum "$TEST_DIR/received_fec.bin" | cut -d" " -f1)
    if [ "$SOURCE_HASH" != "$FEC_HASH" ]; then
        echo "ERROR: FEC file checksum mismatch!"
        exit 1
    fi

    # Cleanup Run 1
    kill $PID_WEBSERVER $PID_TUND_CLIENT $PID_TUND_HOST $PID_CLIENT $PID_HOST
    wait
    rm -f "$TEST_DIR/received_fec.bin"
    echo ""

    # ========================================================
    # RUN 2: Vanilla Reliable QUIC Stream Mode
    # ========================================================
    echo "=== RUN 2: Vanilla Reliable QUIC Stream Mode ==="
    ip netns exec ns_host ./bishlinkd --listen 8888 --bind 192.168.1.1 --socket bishlink-data --track tund/tun-client --reliable > logs/host_reliable.log 2>&1 &
    PID_HOST=$!
    ip netns exec ns_client ./bishlinkd --peer 192.168.1.1:8888 --socket bishlink-data-client --track tund/tun-host --reliable > logs/client_reliable.log 2>&1 &
    PID_CLIENT=$!
    sleep 2

    ip netns exec ns_host ./bishlink-tund --socket bishlink-data -i tun-host -a 10.8.0.1/24 --track tund/tun-host --reliable > logs/tund_host_reliable.log 2>&1 &
    PID_TUND_HOST=$!
    ip netns exec ns_client ./bishlink-tund --socket bishlink-data-client -i tun-client -a 10.8.0.2/24 --track tund/tun-client --reliable > logs/tund_client_reliable.log 2>&1 &
    PID_TUND_CLIENT=$!
    sleep 2

    # Measure latency over Reliable stream tunnel before transfer
    echo "Measuring RTT latency over Reliable Stream tunnel..."
    LATENCY_REL=$(ip netns exec ns_host ping -c 5 -W 1 10.8.0.2 | python3 -c "
import re, sys
m = re.search(r\"rtt min/avg/max/mdev = ([0-9.]+)/([0-9.]+)/([0-9.]+)\", sys.stdin.read())
print(m.group(2) + \" ms\" if m else \"N/A\")
")
    echo "Reliable Latency: $LATENCY_REL"

    ip netns exec ns_host python3 -m http.server --directory "$TEST_DIR" --bind 10.8.0.1 8080 > /dev/null 2>&1 &
    PID_WEBSERVER=$!
    sleep 1

    echo "Downloading 16MB file over Reliable Stream tunnel..."
    START_REL=$(python3 -c "import time; print(time.time())")
    ip netns exec ns_client curl -s -o "$TEST_DIR/received_reliable.bin" http://10.8.0.1:8080/test_16mb.bin
    END_REL=$(python3 -c "import time; print(time.time())")
    DURATION_REL=$(python3 -c "print(round($END_REL - $START_REL, 3))")
    THROUGHPUT_REL=$(python3 -c "print(round(16.0 / $DURATION_REL, 3))")
    echo "Reliable Stream Duration: ${DURATION_REL}s (Throughput: ${THROUGHPUT_REL} MB/s)"

    REL_HASH=$(sha256sum "$TEST_DIR/received_reliable.bin" | cut -d" " -f1)
    if [ "$SOURCE_HASH" != "$REL_HASH" ]; then
        echo "ERROR: Reliable file checksum mismatch!"
        exit 1
    fi

    # Cleanup Run 2
    kill $PID_WEBSERVER $PID_TUND_CLIENT $PID_TUND_HOST $PID_CLIENT $PID_HOST
    wait
    rm -rf "$TEST_DIR"
    ip netns del ns_host
    ip netns del ns_client
    echo ""

    # ========================================================
    # Benchmark Results
    # ========================================================
    echo "=== BENCHMARK COMPARISON ==="
    echo "Network Packet Loss: Gilbert-Elliot Burst (p=5%, r=50%, bad=100%, good=0.5%)"
    echo "File Size: 16 MB"
    echo ""
    echo "FEC Datagram Mode:"
    echo "  - Latency (Avg RTT): $LATENCY_FEC"
    echo "  - Transfer Duration: ${DURATION_FEC}s"
    echo "  - Avg Throughput:    ${THROUGHPUT_FEC} MB/s"
    echo ""
    echo "Reliable Stream Mode:"
    echo "  - Latency (Avg RTT): $LATENCY_REL"
    echo "  - Transfer Duration: ${DURATION_REL}s"
    echo "  - Avg Throughput:    ${THROUGHPUT_REL} MB/s"
    echo ""
    IMPROVEMENT=$(python3 -c "print(round((($DURATION_REL - $DURATION_FEC) / $DURATION_REL) * 100, 1))")
    echo "RaptorQ FEC is ${IMPROVEMENT}% faster than vanilla reliable stream under burst loss."
    echo "============================"
'
