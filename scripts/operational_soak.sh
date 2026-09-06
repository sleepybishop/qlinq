#!/bin/sh

set -eu

duration=${QLINQ_SOAK_SECONDS:-3600}
max_rss_kib=${QLINQ_SOAK_MAX_RSS_KIB:-262144}
case "$duration" in
  ''|*[!0-9]*) echo "QLINQ_SOAK_SECONDS must be a positive integer" >&2; exit 2 ;;
esac
[ "$duration" -gt 0 ] || { echo "QLINQ_SOAK_SECONDS must be positive" >&2; exit 2; }
case "$max_rss_kib" in
  ''|*[!0-9]*) echo "QLINQ_SOAK_MAX_RSS_KIB must be a positive integer" >&2; exit 2 ;;
esac
[ "$max_rss_kib" -gt 0 ] || { echo "QLINQ_SOAK_MAX_RSS_KIB must be positive" >&2; exit 2; }

started=$(date +%s)
deadline=$((started + duration))
iterations=0
cases_run=0
peak_kib=0

run_case() {
  case_name=$1
  executable=$2
  time_file=$(mktemp)
  run_log=$(mktemp)
  if ! /usr/bin/time -f '%M' -o "$time_file" "$executable" >"$run_log" 2>&1; then
    cat "$run_log" >&2
    rm -f "$time_file" "$run_log"
    echo "operational soak case '$case_name' failed after $iterations completed cycles" >&2
    exit 1
  fi
  rss=$(sed -n '$p' "$time_file")
  rm -f "$time_file" "$run_log"
  case "$rss" in
    ''|*[!0-9]*) rss=0 ;;
  esac
  if [ "$rss" -gt "$max_rss_kib" ]; then
    echo "operational soak case '$case_name' exceeded RSS budget: $rss KiB > $max_rss_kib KiB" >&2
    exit 1
  fi
  [ "$rss" -le "$peak_kib" ] || peak_kib=$rss
  cases_run=$((cases_run + 1))
}

while [ "$(date +%s)" -lt "$deadline" ]; do
  run_case lifecycle ./t/00util/test_operational
  run_case recovery ./t/00util/test_transport
  run_case lossy-repair ./t/00util/test_multipath_nack
  iterations=$((iterations + 1))
done

elapsed=$(( $(date +%s) - started ))
echo "operational soak passed: requested_seconds=$duration elapsed_seconds=$elapsed cycles=$iterations cases=$cases_run peak_rss_kib=$peak_kib max_rss_kib=$max_rss_kib"
