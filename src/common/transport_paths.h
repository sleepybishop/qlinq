#ifndef QLINQ_TRANSPORT_PATHS_H
#define QLINQ_TRANSPORT_PATHS_H

#include "pathflow.h"

#include "quicly.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#define TRANSPORT_MAX_QUIC_PATHS 64U
#define TRANSPORT_PATH_BURST_MAX 64U

/* Counter windows belong to one QUIC path, rather than its physical socket.
 * They provide a recent, per-path ACK-rate lower bound for probing. */
typedef struct {
  quicly_path_stats_t baseline;
  uint64_t started_ms, rate_at_ms;
  size_t quic_path;
  uint64_t delivered_bytes_per_second;
  uint64_t probe_rates[4], probe_times[4];
  size_t probe_cursor;
  uint32_t minimum_rtt;
  bool initialized, busy;
} transport_path_measurement_t;

bool transport_path_measure(transport_path_measurement_t *measurement,
                            const quicly_path_stats_t *stats, size_t quic_path,
                            size_t queued_datagrams, uint64_t now_ms);
/* A recent ACK rate is demand-limited on an underused path. It caps the
 * cwnd/RTT estimate only while a busy path has RTT inflation; an absent,
 * stale, or clean-RTT sample deliberately leaves that estimate alone. */
fp_t transport_path_probe_cap(const transport_path_measurement_t *measurement,
                              const quicly_path_stats_t *stats,
                              size_t symbol_size, uint64_t now_ms);

typedef struct {
  fp_t debt, rate;
  uint64_t at_ns;
} transport_path_budget_t;

/* Limit a path to about 50 ms of scheduler-visible work, while retaining a
 * small cold-start burst and never exceeding the QUIC path queue boundary. */
size_t transport_path_budget_burst(fp_t rate);
size_t transport_path_budget_update(transport_path_budget_t *budget, fp_t rate,
                                    uint64_t now_ns);
void transport_path_budget_charge(transport_path_budget_t *budget);
uint64_t transport_path_budget_wait(const transport_path_budget_t *budget,
                                    size_t burst, size_t symbols);

/* Rates are symbol-equivalents/second, latency is seconds, and q counts
 * unsent symbol-equivalents. Missing measurements use independent defaults.
 * The physical egress backlog is shared by all peers using that socket. */
path_t transport_path_estimate(const quicly_path_stats_t *stats,
                               size_t queued_datagrams, size_t egress_bytes,
                               size_t symbol_size, fp_t relative_owd);
/* Smooth rate, latency and loss only on periodic samples. Queue occupancy is
 * always current, including between ticks when another object is published. */
void transport_path_update_state(path_state_t *state, const path_t *sample,
                                 bool periodic);

/* Match the same interface identity as link lookup (IPv6 scope included;
 * transport ports do not identify a physical link). */
bool transport_path_matches_local(const quicly_path_stats_t *stats,
                                  const struct sockaddr_storage *local);

/* Both lookup helpers return SIZE_MAX when no QUIC path matches. */
size_t transport_path_find_by_addresses(quicly_conn_t *quic,
                                        const struct sockaddr *local,
                                        const struct sockaddr *remote);
size_t transport_path_find_by_link(quicly_conn_t *quic,
                                   const struct sockaddr_storage *local_addrs,
                                   size_t num_local_addrs, size_t link_index);
/* Return the matching path and the statistics already read during lookup.
 * Statistics are valid only when the return value is not SIZE_MAX. */
size_t transport_path_get_stats_by_link(
    quicly_conn_t *quic, const struct sockaddr_storage *local_addrs,
    size_t num_local_addrs, size_t link_index, quicly_path_stats_t *stats);
/* SIZE_MAX means the symbol has no allocation; never fall back to path zero. */
size_t transport_path_select_physical(const path_t *paths, size_t num_paths,
                                      size_t packet_index);

#endif
