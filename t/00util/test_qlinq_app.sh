#!/bin/sh
set -eu

tmp_dir=$(mktemp -d /tmp/qlinq-app-test.XXXXXX)
server_pid=
client_pid=
cleanup()
{
    result=$?
    if [ "$result" -ne 0 ]; then
        for log in "$tmp_dir"/*.log "$tmp_dir"/*.tsv; do
            [ -f "$log" ] && tail -40 "$log" >&2
        done
    fi
    if [ -n "$server_pid" ]; then kill "$server_pid" 2>/dev/null || true; fi
    if [ -n "$client_pid" ]; then kill "$client_pid" 2>/dev/null || true; fi
    rm -rf "$tmp_dir"
}
trap cleanup EXIT INT TERM

timeout 8 ./qlinq-app \
    --listen 10093 --bind 127.0.0.1 \
    --idle-timeout-ms 60000 \
    --cert t/assets/server.crt --key t/assets/server.key \
    --auth-token app-test --insecure-no-verify \
    --input README.md --message-size 512 --count 1 \
    --wait-subscribers 1 --wait-members 1 \
    --one-shot --drain-ms 500 --mode rateless \
    --node-id direct-source --stats-file "$tmp_dir/server.tsv" --pv \
    --flexicast --flexicast-cc adaptive \
    --flexicast-cc-startup-rate 64000 \
    --flexicast-cc-min-rate 2000 \
    2>"$tmp_dir/server.log" &
server_pid=$!

timeout 3 ./qlinq-app \
    --peer 127.0.0.1:10093 \
    --idle-timeout-ms 60000 \
    --auth-token app-test --insecure-no-verify \
    --output "$tmp_dir/output.bin" --mode rateless \
    --receive-count 1 --drain-ms 200 \
    --node-id direct-rx --stats-file "$tmp_dir/client.tsv" --pv \
    --flexicast --flexicast-cc adaptive \
    2>"$tmp_dir/client.log" &
client_pid=$!

if ! wait "$server_pid"; then
    server_pid=
    sed -n '1,80p' "$tmp_dir/server.log" >&2
    sed -n '1,80p' "$tmp_dir/client.log" >&2
    exit 1
fi
server_pid=
wait "$client_pid"
client_pid=

test "$(wc -c < "$tmp_dir/output.bin")" -eq 512
cmp -n 512 README.md "$tmp_dir/output.bin"
awk -F '\t' 'NR == 1 { exit !($1 == "elapsed_ms" && $2 == "node" &&
                                  $3 == "tx_objects" && $4 == "rx_objects") }' \
    "$tmp_dir/client.tsv"
awk -F '\t' '$2 == "direct-rx" && $3 == 0 && $4 == 1 && $5 == 512 { ok=1 }
              END { exit !ok }' "$tmp_dir/client.tsv"
awk -F '\t' '$2 == "direct-source" && $15 >= 1 { ok=1 } END { exit !ok }' \
    "$tmp_dir/server.tsv"
awk -F '\t' '$2 == "direct-rx" && $16 >= 1 { ok=1 } END { exit !ok }' \
    "$tmp_dir/client.tsv"
grep -Eq 'qlinq-app: pv .+ tx .+ \[[^]]+/s\] rx .+ \[[^]]+/s\]' \
    "$tmp_dir/server.log"
grep -Eq 'qlinq-app: pv .+ tx .+ \[[^]]+/s\] rx .+ \[[^]]+/s\]' \
    "$tmp_dir/client.log"

timeout 12 ./qlinq-app \
    --listen 10094 --bind 127.0.0.1 \
    --cert t/assets/server.crt --key t/assets/server.key \
    --auth-token app-loss-test --insecure-no-verify \
    --input src/app/main.c --message-size 512 --count 20 \
    --wait-subscribers 1 --wait-members 1 \
    --one-shot --drain-ms 4000 --mode rateless \
    --flexicast --flexicast-cc adaptive \
    --flexicast-cc-startup-rate 256000 \
    --flexicast-cc-min-rate 2000 \
    --flexicast-cc-max-rate 10000000 \
    --stats-ms 500 \
    2>"$tmp_dir/loss-server.log" &
server_pid=$!

timeout 8 ./qlinq-app \
    --peer 127.0.0.1:10094 \
    --auth-token app-loss-test --insecure-no-verify \
    --output "$tmp_dir/loss-output.bin" --mode rateless \
    --receive-count 20 --drain-ms 300 \
    --node-id loss-rx --stats-file "$tmp_dir/loss-client.tsv" \
    --flexicast --flexicast-cc adaptive --loss 20 --stats-ms 500 \
    2>"$tmp_dir/loss-client.log" &
client_pid=$!

if ! wait "$server_pid"; then
    server_pid=
    sed -n '1,80p' "$tmp_dir/loss-server.log" >&2
    sed -n '1,80p' "$tmp_dir/loss-client.log" >&2
    exit 1
fi
server_pid=
wait "$client_pid"
client_pid=

# Repaired or redundant late symbols must never resurrect a completed object.
test "$(wc -c < "$tmp_dir/loss-output.bin")" -eq 10240
cmp -n 10240 src/app/main.c "$tmp_dir/loss-output.bin"
awk -F '\t' '$2 == "loss-rx" && $3 == 0 && $4 == 20 && $5 == 10240 { ok=1 }
              END { exit !ok }' "$tmp_dir/loss-client.tsv"
printf '%s\n' '===QLINQ APP DIRECT API OK==='
