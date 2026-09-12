#!/bin/sh
set -eu

tmp_dir=$(mktemp -d /tmp/qlinq-cast-test.XXXXXX)
sender_pid=
receiver_a_pid=
receiver_b_pid=
cleanup()
{
    if [ -n "$sender_pid" ]; then kill "$sender_pid" 2>/dev/null || true; fi
    if [ -n "$receiver_a_pid" ]; then kill "$receiver_a_pid" 2>/dev/null || true; fi
    if [ -n "$receiver_b_pid" ]; then kill "$receiver_b_pid" 2>/dev/null || true; fi
    rm -rf "$tmp_dir"
}
trap cleanup EXIT INT TERM

./qlinq-cast send --verbose --help | grep -q '^usage: .*qlinq-cast send'

QLINQ_CAST_SECRET=cast-test timeout 12 ./qlinq-cast send \
    --bind 127.0.0.1 --port 10095 \
    --cert t/assets/server.crt --key t/assets/server.key --insecure \
    --block-size 4096 --wait-receivers 1 --mode rateless \
    src/app/main.c 2>"$tmp_dir/rateless-send.log" &
sender_pid=$!

QLINQ_CAST_SECRET=cast-test timeout 12 ./qlinq-cast receive \
    --bind 127.0.0.1 --peer 127.0.0.1:10095 --insecure \
    --mode rateless "$tmp_dir/rateless.out" \
    2>"$tmp_dir/rateless-receive.log"

if ! wait "$sender_pid"; then
    sender_pid=
    sed -n '1,100p' "$tmp_dir/rateless-send.log" >&2
    sed -n '1,100p' "$tmp_dir/rateless-receive.log" >&2
    exit 1
fi
sender_pid=
cmp src/app/main.c "$tmp_dir/rateless.out"
grep -q 'delivery complete: receivers=1 confirmed=1 failed=0' \
    "$tmp_dir/rateless-send.log"

QLINQ_CAST_SECRET=cast-test timeout 12 ./qlinq-cast send \
    --bind 127.0.0.1 --port 10096 \
    --cert t/assets/server.crt --key t/assets/server.key --insecure \
    --block-size 2048 --wait-receivers 1 --mode fec - \
    < README.md 2>"$tmp_dir/fec-send.log" &
sender_pid=$!

QLINQ_CAST_SECRET=cast-test timeout 12 ./qlinq-cast receive \
    --bind 127.0.0.1 --peer 127.0.0.1:10096 --insecure \
    --mode fec - >"$tmp_dir/fec.out" 2>"$tmp_dir/fec-receive.log"

if ! wait "$sender_pid"; then
    sender_pid=
    sed -n '1,100p' "$tmp_dir/fec-send.log" >&2
    sed -n '1,100p' "$tmp_dir/fec-receive.log" >&2
    exit 1
fi
sender_pid=
cmp README.md "$tmp_dir/fec.out"
grep -q 'delivery complete: receivers=1 confirmed=1 failed=0' \
    "$tmp_dir/fec-send.log"

QLINQ_CAST_SECRET=cast-test timeout 12 ./qlinq-cast send \
    --bind 127.0.0.1 --port 10097 \
    --cert t/assets/server.crt --key t/assets/server.key --insecure \
    --block-size 1024 --wait-receivers 2 --mode rateless \
    README.md 2>"$tmp_dir/cohort-send.log" &
sender_pid=$!

QLINQ_CAST_SECRET=cast-test timeout 12 ./qlinq-cast receive \
    --bind 127.0.0.1 --peer 127.0.0.1:10097 --insecure \
    --mode rateless "$tmp_dir/cohort-a.out" \
    2>"$tmp_dir/cohort-a.log" &
receiver_a_pid=$!

QLINQ_CAST_SECRET=cast-test timeout 12 ./qlinq-cast receive \
    --bind 127.0.0.1 --peer 127.0.0.1:10097 --insecure \
    --mode rateless "$tmp_dir/cohort-b.out" \
    2>"$tmp_dir/cohort-b.log" &
receiver_b_pid=$!

if ! wait "$receiver_a_pid"; then
    receiver_a_pid=
    sed -n '1,100p' "$tmp_dir/cohort-send.log" >&2
    sed -n '1,100p' "$tmp_dir/cohort-a.log" >&2
    exit 1
fi
receiver_a_pid=
if ! wait "$receiver_b_pid"; then
    receiver_b_pid=
    sed -n '1,100p' "$tmp_dir/cohort-send.log" >&2
    sed -n '1,100p' "$tmp_dir/cohort-b.log" >&2
    exit 1
fi
receiver_b_pid=
if ! wait "$sender_pid"; then
    sender_pid=
    sed -n '1,100p' "$tmp_dir/cohort-send.log" >&2
    exit 1
fi
sender_pid=
cmp README.md "$tmp_dir/cohort-a.out"
cmp README.md "$tmp_dir/cohort-b.out"
grep -q 'delivery complete: receivers=2 confirmed=2 failed=0' \
    "$tmp_dir/cohort-send.log"

: >"$tmp_dir/empty.in"
QLINQ_CAST_SECRET=cast-test timeout 12 ./qlinq-cast send \
    --bind 127.0.0.1 --port 10098 \
    --cert t/assets/server.crt --key t/assets/server.key --insecure \
    --wait-receivers 1 "$tmp_dir/empty.in" \
    2>"$tmp_dir/empty-send.log" &
sender_pid=$!

QLINQ_CAST_SECRET=cast-test timeout 12 ./qlinq-cast receive \
    --bind 127.0.0.1 --peer 127.0.0.1:10098 --insecure \
    "$tmp_dir/empty.out" 2>"$tmp_dir/empty-receive.log"

if ! wait "$sender_pid"; then
    sender_pid=
    sed -n '1,100p' "$tmp_dir/empty-send.log" >&2
    sed -n '1,100p' "$tmp_dir/empty-receive.log" >&2
    exit 1
fi
sender_pid=
test ! -s "$tmp_dir/empty.out"
grep -q 'delivery complete: receivers=1 confirmed=1 failed=0' \
    "$tmp_dir/empty-send.log"

printf '%s\n' '===QLINQ CAST OK==='
