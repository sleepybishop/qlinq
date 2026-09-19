#include "transport_paths.h"

#include <netinet/in.h>
#include <stdint.h>
#include <string.h>

path_t transport_path_estimate(const quicly_path_stats_t *stats,
                               size_t queued_datagrams, size_t egress_bytes,
                               size_t symbol_size, fp_t relative_owd) {
  path_t sample = {.b = FP_FROM_INT(100),
                   .l = FP_FROM_FLOAT(0.050f),
                   .p = FP_FROM_FLOAT(0.01f)};
  if (stats) {
    if (stats->rtt_smoothed > 0) {
      sample.l = FP_FROM_INT(stats->rtt_smoothed) / 2000;
      if (stats->cwnd > 0 && symbol_size > 0) {
        /* Preserve fractional symbols and sub-one-symbol/second rates.
         * Wide arithmetic also handles unusually large windows and sizes. */
        fp_wide_t rate = (fp_wide_t)stats->cwnd * 1000 * FP_ONE /
                         ((fp_wide_t)symbol_size * stats->rtt_smoothed);
        fp_t ceiling = FP_FROM_INT(FP_SAFE_WHOLE);
        sample.b = rate > ceiling ? ceiling : (rate > 0 ? (fp_t)rate : 1);
      }
    }
    if (stats->sent > 0) {
      uint64_t lost = stats->lost < stats->sent ? stats->lost : stats->sent;
      sample.p = (fp_t)((fp_wide_t)lost * FP_ONE / stats->sent);
    }
  }
  if (relative_owd > 0)
    sample.l = FP_ADD(sample.l, relative_owd);

  /* Quicly's frames are one FEC symbol each (small control frames count
   * conservatively as one). Egress contains serialized UDP payload bytes.
   * The two queues are disjoint; bytes in flight are deliberately excluded. */
  size_t egress_symbols =
      symbol_size == 0
          ? 0
          : egress_bytes / symbol_size + (egress_bytes % symbol_size != 0);
  sample.q =
      queued_datagrams > FP_SAFE_WHOLE ? FP_SAFE_WHOLE : queued_datagrams;
  sample.q += egress_symbols > FP_SAFE_WHOLE - sample.q
                  ? FP_SAFE_WHOLE - sample.q
                  : egress_symbols;
  return sample;
}

void transport_path_update_state(path_state_t *state, const path_t *sample,
                                 bool periodic) {
  if (!state->initialized || periodic)
    pathflow_update_state(state, sample->b, sample->l, sample->p, sample->q,
                          FP_FROM_FLOAT(0.1f));
  /* An integer EWMA can hide small queues indefinitely and retain a phantom
   * backlog after draining. Keep the existing field name for pathflow. */
  state->q_ewma = sample->q;
}

static bool sockaddr_endpoint_equal(const struct sockaddr *a,
                                    const struct sockaddr *b) {
  if (!a || !b || a->sa_family != b->sa_family)
    return false;
  if (a->sa_family == AF_INET) {
    const struct sockaddr_in *a4 = (const struct sockaddr_in *)a;
    const struct sockaddr_in *b4 = (const struct sockaddr_in *)b;
    return a4->sin_port == b4->sin_port &&
           a4->sin_addr.s_addr == b4->sin_addr.s_addr;
  }
  if (a->sa_family == AF_INET6) {
    const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)a;
    const struct sockaddr_in6 *b6 = (const struct sockaddr_in6 *)b;
    return a6->sin6_port == b6->sin6_port &&
           a6->sin6_scope_id == b6->sin6_scope_id &&
           memcmp(&a6->sin6_addr, &b6->sin6_addr, sizeof(a6->sin6_addr)) == 0;
  }
  return false;
}

bool transport_path_measure(transport_path_measurement_t *m,
                            const quicly_path_stats_t *stats, size_t quic_path,
                            size_t queued_datagrams, uint64_t now_ms) {
  if (!m || !stats)
    return false;
  bool busy = queued_datagrams != 0 ||
              (stats->cwnd != 0 && stats->bytes_in_flight >= stats->cwnd / 2);
  bool reset =
      !m->initialized || m->quic_path != quic_path || now_ms < m->started_ms ||
      stats->acked < m->baseline.acked ||
      stats->bytes_acked < m->baseline.bytes_acked ||
      stats->sent < m->baseline.sent ||
      !sockaddr_endpoint_equal(&stats->local.sa, &m->baseline.local.sa) ||
      !sockaddr_endpoint_equal(&stats->remote.sa, &m->baseline.remote.sa);
  if (reset) {
    memset(m, 0, sizeof(*m));
    m->baseline = *stats;
    m->quic_path = quic_path;
    m->started_ms = now_ms;
    m->minimum_rtt = stats->rtt_smoothed;
    m->busy = busy;
    m->initialized = true;
    return true;
  }
  if (stats->rtt_smoothed &&
      (!m->minimum_rtt || stats->rtt_smoothed < m->minimum_rtt))
    m->minimum_rtt = stats->rtt_smoothed;
  m->busy = m->busy && busy;
  uint64_t window_ms = (uint64_t)stats->rtt_smoothed * 2;
  if (window_ms < 100)
    window_ms = 100;
  if (window_ms > 1000)
    window_ms = 1000;
  uint64_t elapsed = now_ms - m->started_ms;
  if (elapsed < window_ms)
    return false;
  uint64_t delivered = stats->bytes_acked - m->baseline.bytes_acked;
  fp_wide_t rate = (fp_wide_t)delivered * 1000 / elapsed;
  uint64_t observed = rate > UINT64_MAX ? UINT64_MAX : (uint64_t)rate;
  m->probe_rates[m->probe_cursor] = observed;
  m->probe_times[m->probe_cursor] = now_ms;
  m->probe_cursor = (m->probe_cursor + 1U) % 4U;
  if (m->busy && delivered != 0) {
    m->delivered_bytes_per_second = observed;
    m->rate_at_ms = now_ms;
  }
  m->baseline = *stats;
  m->started_ms = now_ms;
  m->busy = busy;
  return false;
}

fp_t transport_path_probe_cap(const transport_path_measurement_t *m,
                              const quicly_path_stats_t *stats,
                              size_t symbol_size, uint64_t now_ms) {
  fp_t ceiling = FP_FROM_INT(FP_SAFE_WHOLE);
  if (!m || !stats || !m->initialized || !symbol_size || now_ms < m->started_ms)
    return ceiling;
  uint64_t lifetime = (uint64_t)stats->rtt_smoothed * 8;
  if (lifetime < 500)
    lifetime = 500;
  uint64_t peak = 0;
  for (size_t i = 0; i < 4; i++)
    if (now_ms >= m->probe_times[i] && now_ms - m->probe_times[i] <= lifetime &&
        m->probe_rates[i] > peak)
      peak = m->probe_rates[i];
  if (peak == 0)
    return ceiling;
  uint64_t slack = m->minimum_rtt / 8;
  if (slack < 5)
    slack = 5;
  /* Delivery rate is demand-limited on an underused path.  It becomes a
   * capacity ceiling only when the same busy path shows a sustained RTT
   * increase; otherwise preserve the cwnd / RTT estimate so the scheduler can
   * continue probing independent links. */
  if (!m->busy || !m->minimum_rtt ||
      (uint64_t)stats->rtt_smoothed <= m->minimum_rtt + slack)
    return ceiling;
  fp_wide_t cap = (fp_wide_t)peak * FP_ONE / ((fp_wide_t)symbol_size + 80U);
  return cap > ceiling ? ceiling : (cap > 0 ? (fp_t)cap : 1);
}

size_t transport_path_budget_burst(fp_t rate) {
  fp_wide_t symbols =
      ((fp_wide_t)(rate > 0 ? rate : FP_ONE) + 20 * FP_ONE - 1) / (20 * FP_ONE);
  size_t burst = symbols > SIZE_MAX ? SIZE_MAX : (size_t)symbols;
  if (burst < 8)
    burst = 8;
  if (burst > TRANSPORT_PATH_BURST_MAX)
    burst = TRANSPORT_PATH_BURST_MAX;
  return burst;
}

size_t transport_path_budget_update(transport_path_budget_t *budget, fp_t rate,
                                    uint64_t now_ns) {
  if (!budget)
    return SIZE_MAX;
  if (now_ns < budget->at_ns)
    budget->debt = 0;
  fp_wide_t drained = (fp_wide_t)budget->rate *
                      (now_ns >= budget->at_ns ? now_ns - budget->at_ns : 0) /
                      1000000000U;
  budget->debt = drained >= budget->debt ? 0 : budget->debt - (fp_t)drained;
  budget->at_ns = now_ns;
  budget->rate = rate > 0 ? rate : 1;
  return (size_t)((budget->debt + FP_ONE - 1) / FP_ONE);
}

void transport_path_budget_charge(transport_path_budget_t *budget) {
  if (budget)
    budget->debt += FP_ONE;
}

uint64_t transport_path_budget_wait(const transport_path_budget_t *budget,
                                    size_t burst, size_t symbols) {
  if (!budget || symbols > burst)
    return UINT64_MAX;
  fp_t required = FP_FROM_INT(burst - symbols);
  if (budget->debt <= required)
    return 0;
  if (budget->rate <= 0)
    return UINT64_MAX;
  fp_wide_t needed = budget->debt - required;
  fp_wide_t ns = (needed * 1000000000U + budget->rate - 1) / budget->rate;
  return ns > UINT64_MAX ? UINT64_MAX : (uint64_t)ns;
}

static bool sockaddr_address_equal(const struct sockaddr *a,
                                   const struct sockaddr *b) {
  if (!a || !b || a->sa_family != b->sa_family)
    return false;
  if (a->sa_family == AF_INET)
    return ((const struct sockaddr_in *)a)->sin_addr.s_addr ==
           ((const struct sockaddr_in *)b)->sin_addr.s_addr;
  if (a->sa_family == AF_INET6) {
    const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)a;
    const struct sockaddr_in6 *b6 = (const struct sockaddr_in6 *)b;
    return a6->sin6_scope_id == b6->sin6_scope_id &&
           memcmp(&a6->sin6_addr, &b6->sin6_addr, sizeof(a6->sin6_addr)) == 0;
  }
  return false;
}

bool transport_path_matches_local(const quicly_path_stats_t *stats,
                                  const struct sockaddr_storage *local) {
  return stats && local &&
         sockaddr_address_equal(&stats->local.sa,
                                (const struct sockaddr *)local);
}

size_t transport_path_find_by_addresses(quicly_conn_t *quic,
                                        const struct sockaddr *local,
                                        const struct sockaddr *remote) {
  if (!quic || !local || !remote)
    return SIZE_MAX;
  for (size_t p = 0; p < TRANSPORT_MAX_QUIC_PATHS; p++) {
    quicly_path_stats_t stats;
    if (quicly_get_path_stats(quic, p, &stats) == 0 &&
        sockaddr_endpoint_equal(&stats.local.sa, local) &&
        sockaddr_endpoint_equal(&stats.remote.sa, remote))
      return p;
  }
  return SIZE_MAX;
}

size_t transport_path_find_by_link(quicly_conn_t *quic,
                                   const struct sockaddr_storage *local_addrs,
                                   size_t num_local_addrs, size_t link_index) {
  quicly_path_stats_t stats;
  return transport_path_get_stats_by_link(quic, local_addrs, num_local_addrs,
                                          link_index, &stats);
}

size_t transport_path_get_stats_by_link(
    quicly_conn_t *quic, const struct sockaddr_storage *local_addrs,
    size_t num_local_addrs, size_t link_index, quicly_path_stats_t *stats) {
  if (!quic || !local_addrs || !stats || link_index >= num_local_addrs)
    return SIZE_MAX;
  for (size_t p = 0; p < TRANSPORT_MAX_QUIC_PATHS; p++) {
    if (quicly_get_path_stats(quic, p, stats) == 0 &&
        transport_path_matches_local(stats, &local_addrs[link_index]))
      return p;
  }
  return SIZE_MAX;
}

size_t transport_path_select_physical(const path_t *paths, size_t num_paths,
                                      size_t packet_index) {
  if (!paths || num_paths == 0)
    return SIZE_MAX;
  for (size_t i = 0; i < num_paths; i++) {
    if (packet_index < paths[i].x)
      return i;
    packet_index -= paths[i].x;
  }
  return SIZE_MAX;
}
