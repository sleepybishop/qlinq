/* qlinq-app: direct transport exerciser and stream/file bridge. */

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "portable_sockets.h"
#include "transport.h"

#include <errno.h>
#include <inttypes.h>
#include <openssl/crypto.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define APP_MAX_TRANSPORTS 16
#define APP_MAX_MESSAGE_SIZE TRANSPORT_MAX_FEC_OBJECT_SIZE
#define APP_DEFAULT_RECONNECT_MS 1000U
#define APP_REORDER_OBJECTS 256U
#define APP_REORDER_MAX_BYTES (64U * 1024U * 1024U)
#define APP_PV_INTERVAL_MS 1000U

typedef struct app_ctx_s app_ctx_t;

typedef struct {
  uint8_t *data;
  size_t size;
  uint64_t object_id;
  bool active;
} app_reorder_entry_t;

typedef struct {
  uint32_t interface_index;
  char local_address[64];
  uint64_t bytes_sent;
  uint64_t bytes_received;
  bool initialized;
} pv_path_t;

typedef struct {
  app_ctx_t *app;
  transport_t *transport;
  transport_config_t config;
  char remote_host[256];
  int64_t next_reconnect_at;
  bool is_server;
  bool reconnect_pending;
} app_transport_t;

struct app_ctx_s {
  app_transport_t transports[APP_MAX_TRANSPORTS];
  size_t num_transports;
  moq_track_id_t track;
  const uint8_t *auth_token;
  size_t auth_token_len;
  FILE *input;
  FILE *output;
  FILE *stats_output;
  const char *node_id;
  uint8_t *message;
  size_t message_capacity;
  size_t pending_size;
  uint64_t pending_mask;
  uint64_t next_object_id;
  bool receive_unsubscribed;
  uint64_t sent_objects;
  uint64_t received_objects;
  uint64_t received_bytes;
  uint64_t count_limit;
  uint64_t receive_limit;
  uint32_t interval_ms;
  uint32_t drain_ms;
  uint32_t leave_after_ms;
  uint32_t stats_ms;
  uint32_t reconnect_ms;
  uint32_t start_delay_ms;
  int64_t next_send_at;
  int64_t next_stats_at;
  int64_t eof_at;
  int64_t track_finished_at;
  int64_t receive_done_at;
  int64_t receive_unsubscribed_at;
  int64_t membership_joined_at;
  int64_t publication_ready_at;
  int64_t started_at;
  int64_t pv_last_at;
  int64_t next_pv_at;
  size_t subscriptions;
  size_t required_subscriptions;
  size_t required_flexicast_members;
  bool input_eof;
  bool input_ready;
  bool publication_ready;
  bool track_finished;
  bool one_shot;
  bool pv;
  bool late_join;
  bool reorder_initialized;
  bool verbose;
  bool failed;
  uint64_t reorder_group_id;
  uint64_t reorder_next_object_id;
  size_t reorder_bytes;
  app_reorder_entry_t reorder[APP_REORDER_OBJECTS];
  pv_path_t pv_paths[APP_MAX_TRANSPORTS][TRANSPORT_MAX_PATHS];
};

static volatile sig_atomic_t app_running = 1;

static void handle_signal(int sig) {
  (void)sig;
  app_running = 0;
}

static void show_help(FILE *out, const char *program) {
  fprintf(
      out,
      "usage: %s [network options] [I/O options]\n\n"
      "Network:\n"
      "  --listen PORT                 listen for peers\n"
      "  --peer HOST[:PORT]            connect to a peer (repeatable)\n"
      "  --reconnect-ms MS             peer reconnect delay (default 1000; 0 "
      "disables)\n"
      "  --idle-timeout-ms MS          QUIC control-session idle timeout\n"
      "  --bind ADDRESS                numeric local address\n"
      "  --cert FILE --key FILE        local TLS identity\n"
      "  --ca FILE                     peer CA bundle\n"
      "  --auth-token TOKEN            application authentication token\n"
      "  --insecure-no-verify          test-only certificate bypass\n"
      "  --max-connections N           connection/Flexicast member capacity\n"
      "  --max-repair-requests N       per-peer repair requests/second\n"
      "  --max-aggregate-repairs N     source-wide repair requests/second\n"
      "  --repair-feedback-seed N      deterministic scenario feedback seed\n"
      "  --repair-shadow-file FILE     record M4 repair-planner snapshots\n"
      "  --repair-shadow-deadline MS   planner resource horizon (default 1000)\n"
      "  --loss PERCENT                simulated inbound packet loss\n\n"
      "Data:\n"
      "  --track NAME                  track name (default qlinq-app/data)\n"
      "  --mode datagram|fec|rateless|reliable\n"
      "  --repair-mode auto|indexed|rateless\n"
      "  --input FILE|-                publish fixed-size records\n"
      "  --output FILE|-               write received object payloads\n"
      "  --message-size BYTES          input record size (default 1200)\n"
      "  --count N                     stop reading after N records\n"
      "  --receive-count N             exit after receiving N records\n"
      "  --leave-after-ms MS           leave after MS of active membership\n"
      "  --late-join                   begin ordered output at first object seen\n"
      "  --wait-subscribers N          initial subscribers before sending\n"
      "  --wait-members N              initial Flexicast members before sending\n"
      "  --start-delay-ms MS           delay sending after readiness\n"
      "  --interval-ms MS              minimum interval between records\n"
      "  --one-shot                    exit after input drains\n"
      "  --drain-ms MS                 one-shot drain time (default 1000)\n"
      "  --stats-ms MS                 periodically print transport stats\n\n"
      "  --stats-file FILE             write machine-readable TSV telemetry\n"
      "  --node-id ID                  node label used in telemetry\n\n"
      "  --pv                          pv-style throughput per interface\n"
      "  --verbose\n\n"
      "Flexicast:\n"
      "  --flexicast\n"
      "  --flexicast-group GROUP --flexicast-port PORT\n"
      "  --flexicast-interface ADDRESS\n"
      "  --flexicast-cc multicast|adaptive\n"
      "  --flexicast-repair-route shared|unicast (experiment only)\n"
      "  --flexicast-cc-startup-rate BYTES_PER_SECOND\n"
      "  --flexicast-cc-min-rate BYTES_PER_SECOND\n"
      "  --flexicast-cc-max-rate BYTES_PER_SECOND\n"
      "  --flexicast-cc-aggregate-rate BYTES_PER_SECOND\n"
      "  --flexicast-cc-feedback-timeout MS\n",
      program);
}

static bool parse_u64(const char *text, uint64_t maximum, uint64_t *value) {
  char *end = NULL;
  unsigned long long parsed;
  if (!text || !text[0] || text[0] == '-' || !value)
    return false;
  errno = 0;
  parsed = strtoull(text, &end, 10);
  if (errno != 0 || !end || *end != '\0' || parsed > maximum)
    return false;
  *value = (uint64_t)parsed;
  return true;
}

static bool parse_peer(const char *endpoint, char *host, size_t host_capacity,
                       uint16_t *port) {
  const char *start = endpoint, *port_text = NULL;
  size_t host_len;
  uint64_t parsed_port;
  if (!endpoint || !endpoint[0] || !host || host_capacity == 0 || !port)
    return false;
  host_len = strlen(endpoint);
  if (endpoint[0] == '[') {
    const char *closing = strchr(endpoint + 1, ']');
    if (!closing || (closing[1] != '\0' && closing[1] != ':'))
      return false;
    start = endpoint + 1;
    host_len = (size_t)(closing - start);
    if (closing[1] == ':')
      port_text = closing + 2;
  } else {
    const char *first = strchr(endpoint, ':');
    const char *last = strrchr(endpoint, ':');
    if (first && first == last) {
      host_len = (size_t)(first - endpoint);
      port_text = first + 1;
    }
  }
  if (host_len == 0 || host_len >= host_capacity)
    return false;
  if (port_text) {
    if (!parse_u64(port_text, UINT16_MAX, &parsed_port) || parsed_port == 0)
      return false;
    *port = (uint16_t)parsed_port;
  }
  memcpy(host, start, host_len);
  host[host_len] = '\0';
  return true;
}

static void subscribe(app_transport_t *transport, transport_conn_t *conn) {
  if (!transport_subscribe_conn(transport->transport, conn,
                                transport->app->track)) {
    fprintf(stderr, "qlinq-app: unable to subscribe to '%s'\n",
            transport->app->track.name);
    transport->app->failed = true;
  }
}

static bool write_received_payload(app_ctx_t *app,
                                   const moq_track_id_t *track_id,
                                   const uint8_t *payload,
                                   size_t payload_size) {
  const uint8_t *data = payload;
  size_t remaining = payload_size;
  if (track_id->type == MOQ_TRACK_DATA &&
      (track_id->flags & MOQ_TRACK_FLAG_FEC_ENABLED) != 0) {
    while (remaining != 0) {
      uint16_t record_size;
      if (remaining < 2)
        return false;
      memcpy(&record_size, data, 2);
      record_size = ntohs(record_size);
      data += 2;
      remaining -= 2;
      if (record_size == 0 || record_size > remaining)
        return false;
      if (app->output &&
          fwrite(data, 1, record_size, app->output) != record_size)
        return false;
      app->received_objects++;
      app->received_bytes += record_size;
      data += record_size;
      remaining -= record_size;
    }
  } else {
    if (app->output && remaining != 0 &&
        fwrite(data, 1, remaining, app->output) != remaining)
      return false;
    app->received_objects++;
    app->received_bytes += remaining;
  }
  if (app->receive_limit != 0 && app->received_objects >= app->receive_limit &&
      app->receive_done_at == 0)
    app->receive_done_at = transport_get_time_ms();
  if (app->output)
    fflush(app->output);
  return true;
}

static bool write_received_object(app_ctx_t *app,
                                  const transport_event_t *event) {
  bool ordered_data = event->track_id.type == MOQ_TRACK_DATA &&
                      (event->track_id.flags & MOQ_TRACK_FLAG_FEC_ENABLED) != 0;
  if (!ordered_data)
    return write_received_payload(app, &event->track_id, event->object.data,
                                  event->object.size);

  if (!app->reorder_initialized) {
    app->reorder_initialized = true;
    app->reorder_group_id = event->object.group_id;
    app->reorder_next_object_id =
        app->late_join ? event->object.object_id : 0;
  }
  if (event->object.group_id != app->reorder_group_id)
    return false;
  if (event->object.object_id < app->reorder_next_object_id)
    return true;
  uint64_t distance =
      event->object.object_id - app->reorder_next_object_id;
  if (distance >= APP_REORDER_OBJECTS ||
      event->object.size > APP_REORDER_MAX_BYTES - app->reorder_bytes)
    return false;
  size_t slot = (size_t)(event->object.object_id % APP_REORDER_OBJECTS);
  app_reorder_entry_t *entry = &app->reorder[slot];
  if (entry->active)
    return entry->object_id == event->object.object_id;
  entry->data = malloc(event->object.size);
  if (!entry->data)
    return false;
  memcpy(entry->data, event->object.data, event->object.size);
  entry->size = event->object.size;
  entry->object_id = event->object.object_id;
  entry->active = true;
  app->reorder_bytes += entry->size;

  while (true) {
    slot = (size_t)(app->reorder_next_object_id % APP_REORDER_OBJECTS);
    entry = &app->reorder[slot];
    if (!entry->active || entry->object_id != app->reorder_next_object_id)
      break;
    if (!write_received_payload(app, &event->track_id, entry->data,
                                entry->size))
      return false;
    app->reorder_bytes -= entry->size;
    free(entry->data);
    memset(entry, 0, sizeof(*entry));
    app->reorder_next_object_id++;
  }
  return true;
}

static void reset_reorder(app_ctx_t *app) {
  for (size_t i = 0; i < APP_REORDER_OBJECTS; i++) {
    free(app->reorder[i].data);
    memset(&app->reorder[i], 0, sizeof(app->reorder[i]));
  }
  app->reorder_initialized = false;
  app->reorder_group_id = 0;
  app->reorder_next_object_id = 0;
  app->reorder_bytes = 0;
}

static void on_transport_event(void *user_data,
                               const transport_event_t *event) {
  app_transport_t *transport = user_data;
  app_ctx_t *app = transport->app;
  switch (event->type) {
  case TRANSPORT_EVENT_CONNECTED:
    transport->reconnect_pending = false;
    if (app->verbose)
      fprintf(stderr, "qlinq-app: peer connected\n");
    if (!transport->is_server &&
        !transport_send_auth(transport->transport, event->conn, app->auth_token,
                             app->auth_token_len))
      app->failed = true;
    break;
  case TRANSPORT_EVENT_AUTH:
    if (transport->is_server) {
      bool accepted = event->auth.token_len == app->auth_token_len &&
                      CRYPTO_memcmp(event->auth.token, app->auth_token,
                                    app->auth_token_len) == 0;
      if (!transport_respond_auth(transport->transport, event->conn, accepted))
        app->failed = true;
      if (accepted)
        subscribe(transport, event->conn);
    }
    break;
  case TRANSPORT_EVENT_AUTH_COMPLETE:
    if (event->auth.success)
      subscribe(transport, event->conn);
    else
      app->failed = true;
    break;
  case TRANSPORT_EVENT_SUBSCRIBE:
    if (event->track_id.type == app->track.type &&
        strcmp(event->track_id.name, app->track.name) == 0)
      app->subscriptions++;
    break;
  case TRANSPORT_EVENT_UNSUBSCRIBE:
    if (event->track_id.type == app->track.type &&
        strcmp(event->track_id.name, app->track.name) == 0 &&
        app->subscriptions != 0)
      app->subscriptions--;
    break;
  case TRANSPORT_EVENT_OBJECT:
    if (event->track_id.type != app->track.type ||
        strcmp(event->track_id.name, app->track.name) != 0)
      break;
    if (!write_received_object(app, event)) {
      fprintf(stderr,
              "qlinq-app: malformed recovered object or output error\n");
      app->failed = true;
    }
    break;
  case TRANSPORT_EVENT_DISCONNECTED:
    if (app->verbose)
      fprintf(stderr, "qlinq-app: peer disconnected\n");
    if (!transport->is_server && app->reconnect_ms != 0) {
      reset_reorder(app);
      transport->reconnect_pending = true;
      transport->next_reconnect_at =
          transport_get_time_ms() + app->reconnect_ms;
    }
    break;
  case TRANSPORT_EVENT_OBJECT_LOST:
    if (app->verbose)
      fprintf(stderr, "qlinq-app: object recovery failed\n");
    break;
  case TRANSPORT_EVENT_TRACK_FINISHED:
    if (app->verbose)
      fprintf(stderr, "qlinq-app: track recovery finished\n");
    break;
  case TRANSPORT_EVENT_TRACK_DRAINED:
    if (app->verbose)
      fprintf(stderr, "qlinq-app: track delivery drained\n");
    break;
  case TRANSPORT_EVENT_TRACK_ABORTED:
    if (app->verbose)
      fprintf(stderr, "qlinq-app: track aborted by peer\n");
    break;
  case TRANSPORT_EVENT_KEYFRAME_REQUEST:
    break;
  }
}

static bool transports_ready(app_ctx_t *app) {
  if (app->publication_ready)
    return transport_get_time_ms() >= app->publication_ready_at;
  if (app->subscriptions < app->required_subscriptions)
    return false;
  if (app->required_flexicast_members != 0) {
    size_t members = 0;
    for (size_t i = 0; i < app->num_transports; i++) {
      transport_stats_t stats = {0};
      if (!app->transports[i].transport ||
          !transport_get_stats(app->transports[i].transport, &stats))
        return false;
      members += stats.flexicast_active_members;
    }
    if (members < app->required_flexicast_members)
      return false;
  }
  for (size_t i = 0; i < app->num_transports; i++)
    if (!app->transports[i].transport ||
        !transport_is_track_ready(app->transports[i].transport, &app->track))
      return false;
  app->publication_ready = true;
  int64_t now = transport_get_time_ms();
  app->publication_ready_at =
      app->start_delay_ms > (uint64_t)(INT64_MAX - now)
          ? INT64_MAX
          : now + (int64_t)app->start_delay_ms;
  return app->start_delay_ms == 0;
}

static bool receive_track_end_observed(const app_ctx_t *app) {
  if ((app->track.flags & MOQ_TRACK_FLAG_FEC_RATELESS) == 0)
    return true;

  bool found = false;
  for (size_t i = 0; i < app->num_transports; i++) {
    const app_transport_t *entry = &app->transports[i];
    transport_stats_t stats = {0};
    if (entry->is_server || !entry->transport)
      continue;
    found = true;
    if (!transport_get_stats(entry->transport, &stats) ||
        stats.track_ends_received == 0)
      return false;
  }
  return found;
}

static size_t active_receive_memberships(const app_ctx_t *app) {
  size_t memberships = 0;
  for (size_t i = 0; i < app->num_transports; i++) {
    const app_transport_t *entry = &app->transports[i];
    transport_stats_t stats = {0};
    if (entry->is_server || !entry->transport ||
        !transport_get_stats(entry->transport, &stats))
      continue;
    memberships += stats.flexicast_active_memberships;
  }
  return memberships;
}

static bool unsubscribe_receivers(app_ctx_t *app, int64_t now) {
  bool found = false, succeeded = true;
  for (size_t i = 0; i < app->num_transports; i++) {
    app_transport_t *entry = &app->transports[i];
    if (entry->is_server || !entry->transport)
      continue;
    found = true;
    if (!transport_unsubscribe(entry->transport, app->track))
      succeeded = false;
  }
  if (found && succeeded) {
    app->receive_unsubscribed = true;
    app->receive_unsubscribed_at = now;
    return true;
  }
  return false;
}

static void load_input(app_ctx_t *app, int64_t now) {
  if (!app->input || app->input_eof || app->pending_size != 0 ||
      !app->input_ready || !transports_ready(app) || now < app->next_send_at)
    return;
  if (app->count_limit != 0 && app->sent_objects >= app->count_limit) {
    app->input_eof = true;
    app->eof_at = now;
    return;
  }
  app->input_ready = false;
  ssize_t read_size =
      read(fileno(app->input), app->message, app->message_capacity);
  if (read_size <= 0) {
    if (read_size < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
      return;
    if (read_size < 0) {
      fprintf(stderr, "qlinq-app: input read failed\n");
      app->failed = true;
    } else {
      app->input_eof = true;
      app->eof_at = now;
    }
    return;
  }
  app->pending_size = (size_t)read_size;
  app->pending_mask = app->num_transports == 64
                          ? UINT64_MAX
                          : (UINT64_C(1) << app->num_transports) - 1;
}

static void publish_pending(app_ctx_t *app, int64_t now) {
  if (app->pending_size == 0)
    return;
  moq_object_t object = {.track_id = app->track,
                         .group_id = 0,
                         .object_id = app->next_object_id,
                         .data = app->message,
                         .size = app->pending_size,
                         .priority = 1};
  for (size_t i = 0; i < app->num_transports; i++) {
    uint64_t bit = UINT64_C(1) << i;
    if ((app->pending_mask & bit) == 0 || !app->transports[i].transport ||
        !transport_is_track_ready(app->transports[i].transport, &app->track))
      continue;
    transport_publish_result_t result =
        transport_publish_ex(app->transports[i].transport, &object);
    if (result == TRANSPORT_PUBLISH_BACKPRESSURE)
      continue;
    if (result == TRANSPORT_PUBLISH_INVALID ||
        result == TRANSPORT_PUBLISH_ERROR) {
      fprintf(stderr, "qlinq-app: publication failed (%d)\n", result);
      app->failed = true;
      return;
    }
    if (result == TRANSPORT_PUBLISH_PARTIAL)
      fprintf(stderr, "qlinq-app: partial publication on one mesh edge\n");
    app->pending_mask &= ~bit;
  }
  if (app->pending_mask == 0) {
    app->pending_size = 0;
    app->next_object_id++;
    app->sent_objects++;
    app->next_send_at = now + app->interval_ms;
  }
}

static void finish_input_track(app_ctx_t *app, int64_t now) {
  if (!app->input_eof || app->pending_size != 0 || app->track_finished)
    return;
  if ((app->track.flags & MOQ_TRACK_FLAG_FEC_RATELESS) != 0) {
    for (size_t i = 0; i < app->num_transports; i++) {
      if (!app->transports[i].transport ||
          !transport_finish_track(app->transports[i].transport, app->track))
        return;
    }
  }
  app->track_finished = true;
  app->track_finished_at = now;
  app->eof_at = now;
}

static void print_stats(app_ctx_t *app, int64_t now, bool force) {
  if (!force && (app->stats_ms == 0 || now < app->next_stats_at))
    return;
  if (app->stats_ms == 0 && !app->stats_output)
    return;
  uint64_t packets = 0, acks = 0, rate = 0, repair_requests = 0;
  uint64_t repair_symbols = 0, duplicate_objects = 0;
  uint64_t repair_multicast_symbols = 0, repair_requests_suppressed = 0;
  uint64_t repair_requests_aggregate_throttled = 0;
  uint64_t repair_requests_merged = 0, repair_batches_emitted = 0;
  uint64_t repair_requester_records_peak = 0;
  uint64_t repair_requester_overflow = 0, repair_requester_updates = 0;
  uint64_t repair_requester_records_expired = 0;
  uint64_t repair_shadow_plans = 0, repair_shadow_all_shared = 0;
  uint64_t repair_shadow_all_unicast = 0, repair_shadow_mixed = 0;
  uint64_t repair_shadow_uncertain = 0, repair_shadow_infeasible = 0;
  uint64_t repair_shadow_log_errors = 0, repair_shadow_last_airtime_us = 0;
  uint64_t repair_shadow_last_physical_bytes = 0;
  uint32_t repair_shadow_last_savings_ppm = 0;
  uint64_t repair_shadow_observation_overflow = 0;
  uint64_t repair_unicast_symbols = 0, repair_unicast_payload_bytes = 0;
  uint64_t repair_queue_backpressure = 0, repair_physical_bytes = 0;
  uint64_t flexicast_physical_bytes = 0, repair_oldest_age_ms = 0;
  uint64_t repair_packets_cancelled = 0;
  uint64_t repair_pending_symbols_cancelled = 0;
  uint64_t repair_indexed_requests_sent = 0;
  uint64_t repair_rateless_requests_sent = 0;
  uint64_t repair_indexed_requests_received = 0;
  uint64_t repair_rateless_requests_received = 0;
  uint64_t repair_rateless_symbols_sent = 0;
  uint64_t repair_rateless_exhausted = 0;
  uint64_t flexicast_feedback_fallbacks = 0;
  uint64_t track_ends_sent = 0, track_ends_received = 0;
  uint64_t checkpoints_sent = 0, checkpoints_received = 0;
  uint64_t checkpoint_acks_sent = 0, checkpoint_acks_received = 0;
  uint64_t recovery_cache_releases = 0, recovery_cache_backpressure = 0;
  uint64_t recovery_oldest_checkpoint_age_ms = 0;
  uint64_t flexicast_rekeys = 0, flexicast_rekey_members = 0;
  uint64_t flexicast_rekey_batched_changes = 0;
  uint64_t flexicast_membership_joins = 0;
  uint64_t flexicast_membership_leaves = 0, flexicast_fallbacks = 0;
  uint64_t repair_requests_deferred = 0;
  uint64_t cc_rate_increases = 0, cc_rate_reductions = 0;
  uint64_t cc_floor_entries = 0, cc_floor_exits = 0;
  uint64_t cc_ack_growth = 0, cc_other_growth = 0;
  uint64_t cc_loss_reductions = 0, cc_rtt_reductions = 0;
  uint64_t cc_ecn_reductions = 0, cc_timeout_reductions = 0;
  uint64_t cc_rate_limit_reductions = 0, cc_other_reductions = 0;
  uint64_t cc_external_load_growth_freezes = 0;
  size_t members = 0, queued = 0, repair_queued_packets = 0;
  size_t repair_queued_bytes = 0, repair_pending_objects = 0;
  size_t recovery_checkpoints_pending = 0, active_connections = 0;
  size_t assembler_memory_bytes = 0, egress_peak_packets = 0;
  size_t egress_peak_bytes = 0, active_flows = 0, active_memberships = 0;
  for (size_t i = 0; i < app->num_transports; i++) {
    transport_stats_t stats = {0};
    if (!app->transports[i].transport ||
        !transport_get_stats(app->transports[i].transport, &stats))
      continue;
    packets += stats.flexicast_packets_sent;
    acks += stats.flexicast_acks_received;
    repair_requests += stats.repair_requests_sent;
    repair_indexed_requests_sent += stats.repair_indexed_requests_sent;
    repair_rateless_requests_sent += stats.repair_rateless_requests_sent;
    repair_indexed_requests_received += stats.repair_indexed_requests_received;
    repair_rateless_requests_received +=
        stats.repair_rateless_requests_received;
    repair_requests_deferred += stats.repair_requests_deferred;
    repair_symbols += stats.repair_symbols_sent;
    repair_rateless_symbols_sent += stats.repair_rateless_symbols_sent;
    repair_rateless_exhausted += stats.repair_rateless_exhausted;
    repair_multicast_symbols += stats.repair_multicast_symbols_sent;
    repair_requests_suppressed += stats.repair_requests_suppressed;
    repair_requests_aggregate_throttled +=
        stats.repair_requests_aggregate_throttled;
    repair_requests_merged += stats.repair_requests_merged;
    if (stats.repair_requester_records_peak > repair_requester_records_peak)
      repair_requester_records_peak = stats.repair_requester_records_peak;
    repair_requester_overflow += stats.repair_requester_overflow;
    repair_requester_updates += stats.repair_requester_updates;
    repair_requester_records_expired += stats.repair_requester_records_expired;
    repair_shadow_plans += stats.repair_shadow_plans_evaluated;
    repair_shadow_all_shared += stats.repair_shadow_all_shared;
    repair_shadow_all_unicast += stats.repair_shadow_all_unicast;
    repair_shadow_mixed += stats.repair_shadow_mixed;
    repair_shadow_uncertain += stats.repair_shadow_uncertain;
    repair_shadow_infeasible += stats.repair_shadow_infeasible;
    repair_shadow_log_errors += stats.repair_shadow_log_errors;
    repair_shadow_observation_overflow +=
        stats.repair_shadow_observation_overflow;
    repair_unicast_symbols += stats.repair_unicast_symbols_sent;
    repair_unicast_payload_bytes +=
        stats.repair_unicast_payload_bytes_queued;
    if (stats.repair_shadow_last_airtime_us != 0) {
      repair_shadow_last_airtime_us = stats.repair_shadow_last_airtime_us;
      repair_shadow_last_physical_bytes =
          stats.repair_shadow_last_physical_bytes;
      repair_shadow_last_savings_ppm = stats.repair_shadow_last_savings_ppm;
    }
    repair_batches_emitted += stats.repair_batches_emitted;
    repair_queue_backpressure += stats.repair_queue_backpressure;
    repair_packets_cancelled += stats.repair_packets_cancelled;
    repair_pending_symbols_cancelled += stats.repair_pending_symbols_cancelled;
    repair_physical_bytes += stats.repair_physical_bytes_sent;
    flexicast_physical_bytes += stats.flexicast_physical_bytes_sent;
    flexicast_feedback_fallbacks += stats.flexicast_feedback_fallbacks;
    repair_queued_packets += stats.repair_queued_packets;
    repair_queued_bytes += stats.repair_queued_bytes;
    repair_pending_objects += stats.repair_pending_objects;
    if (stats.repair_oldest_age_ms > repair_oldest_age_ms)
      repair_oldest_age_ms = stats.repair_oldest_age_ms;
    duplicate_objects += stats.fec_duplicate_objects_suppressed;
    track_ends_sent += stats.track_ends_sent;
    track_ends_received += stats.track_ends_received;
    checkpoints_sent += stats.recovery_checkpoints_sent;
    checkpoints_received += stats.recovery_checkpoints_received;
    checkpoint_acks_sent += stats.recovery_checkpoint_acks_sent;
    checkpoint_acks_received += stats.recovery_checkpoint_acks_received;
    recovery_cache_releases += stats.recovery_cache_releases;
    recovery_cache_backpressure += stats.recovery_cache_backpressure;
    recovery_checkpoints_pending += stats.recovery_checkpoints_pending;
    if (stats.recovery_oldest_checkpoint_age_ms >
        recovery_oldest_checkpoint_age_ms)
      recovery_oldest_checkpoint_age_ms =
          stats.recovery_oldest_checkpoint_age_ms;
    flexicast_rekeys += stats.flexicast_rekeys;
    flexicast_rekey_members += stats.flexicast_rekey_members;
    flexicast_rekey_batched_changes +=
        stats.flexicast_rekey_batched_changes;
    flexicast_membership_joins += stats.flexicast_membership_joins;
    flexicast_membership_leaves += stats.flexicast_membership_leaves;
    flexicast_fallbacks += stats.flexicast_fallbacks;
    active_connections += stats.active_connections;
    assembler_memory_bytes += stats.assembler_memory_bytes;
    egress_peak_packets += stats.egress_peak_packets;
    egress_peak_bytes += stats.egress_peak_bytes;
    active_flows += stats.flexicast_active_flows;
    active_memberships += stats.flexicast_active_memberships;
    cc_rate_increases += stats.flexicast_cc_rate_increase_events;
    cc_rate_reductions += stats.flexicast_cc_rate_reduction_events;
    cc_floor_entries += stats.flexicast_cc_floor_entry_events;
    cc_floor_exits += stats.flexicast_cc_floor_exit_events;
    cc_ack_growth += stats.flexicast_cc_ack_growth_events;
    cc_other_growth += stats.flexicast_cc_other_growth_events;
    cc_loss_reductions += stats.flexicast_cc_loss_reduction_events;
    cc_rtt_reductions += stats.flexicast_cc_rtt_reduction_events;
    cc_ecn_reductions += stats.flexicast_cc_ecn_reduction_events;
    cc_timeout_reductions += stats.flexicast_cc_timeout_reduction_events;
    cc_rate_limit_reductions += stats.flexicast_cc_rate_limit_reduction_events;
    cc_other_reductions += stats.flexicast_cc_other_reduction_events;
    cc_external_load_growth_freezes +=
        stats.flexicast_cc_external_load_growth_freeze_events;
    members += stats.flexicast_active_members;
    queued += stats.flexicast_queued_packets;
    if (stats.flexicast_cc_rate_bytes_per_second != 0 &&
        (rate == 0 || stats.flexicast_cc_rate_bytes_per_second < rate))
      rate = stats.flexicast_cc_rate_bytes_per_second;
  }
  if (app->stats_ms != 0)
    fprintf(stderr,
            "qlinq-app: node=%s tx=%" PRIu64 " rx=%" PRIu64 " bytes=%" PRIu64
            " fc_packets=%" PRIu64 " acks=%" PRIu64 " repair_req=%" PRIu64
            " repair_symbols=%" PRIu64 " duplicates=%" PRIu64
            " members=%zu queued=%zu rate=%" PRIu64
            " B/s subscribers=%zu track_end_tx=%" PRIu64
            " track_end_rx=%" PRIu64 " checkpoint_tx=%" PRIu64
            " checkpoint_rx=%" PRIu64 " checkpoint_ack_tx=%" PRIu64
            " checkpoint_ack_rx=%" PRIu64 " cache_released=%" PRIu64
            " cache_backpressure=%" PRIu64 " repair_deferred=%" PRIu64
            " repair_batches=%" PRIu64 " repair_queue=%zu"
            " repair_pending=%zu repair_oldest_ms=%" PRIu64
            " repair_airtime=%" PRIu64 " repair_cancelled=%" PRIu64
            " repair_indexed_req=%" PRIu64 " repair_rateless_req=%" PRIu64
            " repair_rateless_symbols=%" PRIu64 "\n",
            app->node_id, app->sent_objects, app->received_objects,
            app->received_bytes, packets, acks, repair_requests, repair_symbols,
            duplicate_objects, members, queued, rate, app->subscriptions,
            track_ends_sent, track_ends_received, checkpoints_sent,
            checkpoints_received, checkpoint_acks_sent,
            checkpoint_acks_received, recovery_cache_releases,
            recovery_cache_backpressure, repair_requests_deferred,
            repair_batches_emitted, repair_queued_packets,
            repair_pending_objects, repair_oldest_age_ms, repair_physical_bytes,
            repair_packets_cancelled, repair_indexed_requests_sent,
            repair_rateless_requests_sent, repair_rateless_symbols_sent);
  if (app->stats_output) {
    fprintf(app->stats_output,
            "%" PRId64 "\t%s\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64
            "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64
            "\t%zu\t%zu\t%zu\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64
            "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64
            "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64,
            now - app->started_at, app->node_id, app->sent_objects,
            app->received_objects, app->received_bytes, packets, acks,
            repair_requests, repair_symbols, duplicate_objects, members, queued,
            app->subscriptions, rate, track_ends_sent, track_ends_received,
            repair_requests_deferred, checkpoints_sent, checkpoints_received,
            checkpoint_acks_sent, checkpoint_acks_received,
            recovery_cache_releases, recovery_cache_backpressure,
            repair_multicast_symbols, repair_requests_suppressed,
            repair_requests_aggregate_throttled);
    fprintf(app->stats_output,
            "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64
            "\t%zu\t%zu\t%zu\t%" PRIu64,
            repair_requests_merged, repair_batches_emitted,
            repair_queue_backpressure, repair_physical_bytes,
            flexicast_physical_bytes, repair_queued_packets,
            repair_queued_bytes, repair_pending_objects, repair_oldest_age_ms);
    fprintf(app->stats_output,
            "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64
            "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64
            "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64
            "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64
            "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64
            "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64
            "\t%" PRIu64 "\t%" PRId64 "\t%" PRId64 "\t%" PRId64
            "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64
            "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64
            "\t%" PRIu64 "\t%u\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64
            "\t%zu\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64
            "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64
            "\t%zu\t%zu\t%zu\t%zu\t%zu\t%zu\n",
            repair_packets_cancelled, repair_pending_symbols_cancelled,
            flexicast_feedback_fallbacks, repair_indexed_requests_sent,
            repair_rateless_requests_sent, repair_indexed_requests_received,
            repair_rateless_requests_received, repair_rateless_symbols_sent,
            repair_rateless_exhausted, repair_requester_records_peak,
            repair_requester_overflow, repair_requester_updates,
            repair_requester_records_expired, cc_rate_increases,
            cc_rate_reductions, cc_floor_entries, cc_floor_exits, cc_ack_growth,
            cc_other_growth, cc_loss_reductions, cc_rtt_reductions,
            cc_ecn_reductions, cc_timeout_reductions,
            cc_rate_limit_reductions, cc_other_reductions,
            cc_external_load_growth_freezes, now, app->track_finished_at,
            app->receive_done_at, repair_shadow_plans,
            repair_shadow_all_shared, repair_shadow_all_unicast,
            repair_shadow_mixed, repair_shadow_uncertain,
            repair_shadow_infeasible, repair_shadow_log_errors,
            repair_shadow_last_airtime_us,
            repair_shadow_last_physical_bytes,
            repair_shadow_last_savings_ppm,
            repair_shadow_observation_overflow, repair_unicast_symbols,
            repair_unicast_payload_bytes, recovery_checkpoints_pending,
            recovery_oldest_checkpoint_age_ms, flexicast_rekeys,
            flexicast_rekey_members, flexicast_rekey_batched_changes,
            flexicast_membership_joins, flexicast_membership_leaves,
            flexicast_fallbacks, active_connections, assembler_memory_bytes,
            egress_peak_packets, egress_peak_bytes, active_flows,
            active_memberships);
    fflush(app->stats_output);
  }
  app->next_stats_at = now + app->stats_ms;
}

static void format_bytes(double bytes, char *output, size_t capacity) {
  static const char *const units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
  size_t unit = 0;
  while (bytes >= 1024.0 && unit + 1 < sizeof(units) / sizeof(units[0])) {
    bytes /= 1024.0;
    unit++;
  }
  if (unit == 0)
    snprintf(output, capacity, "%.0f %s", bytes, units[unit]);
  else
    snprintf(output, capacity, "%.2f %s", bytes, units[unit]);
}

static void print_pv(app_ctx_t *app, int64_t now, bool force) {
  if (!app->pv || (!force && now < app->next_pv_at))
    return;
  int64_t interval_ms = now - app->pv_last_at;
  if (interval_ms <= 0)
    interval_ms = 1;
  uint64_t elapsed_seconds =
      now > app->started_at ? (uint64_t)(now - app->started_at) / 1000U : 0;

  for (size_t transport_index = 0; transport_index < app->num_transports;
       transport_index++) {
    transport_t *transport = app->transports[transport_index].transport;
    if (!transport)
      continue;
    for (size_t path = 0; path < TRANSPORT_MAX_PATHS; path++) {
      transport_path_stats_t stats;
      if (!transport_get_path_stats(transport, path, &stats))
        break;
      pv_path_t *previous = &app->pv_paths[transport_index][path];
      bool same_path = previous->initialized &&
                       previous->interface_index == stats.interface_index &&
                       strcmp(previous->local_address, stats.local_address) == 0;
      uint64_t sent_delta = same_path && stats.bytes_sent >= previous->bytes_sent
                                ? stats.bytes_sent - previous->bytes_sent
                                : stats.bytes_sent;
      uint64_t received_delta =
          same_path && stats.bytes_received >= previous->bytes_received
              ? stats.bytes_received - previous->bytes_received
              : stats.bytes_received;
      double sent_rate = (double)sent_delta * 1000.0 / (double)interval_ms;
      double received_rate =
          (double)received_delta * 1000.0 / (double)interval_ms;

      char sent_total[32], received_total[32], sent_per_second[32];
      char received_per_second[32], label[136];
      format_bytes((double)stats.bytes_sent, sent_total, sizeof(sent_total));
      format_bytes((double)stats.bytes_received, received_total,
                   sizeof(received_total));
      format_bytes(sent_rate, sent_per_second, sizeof(sent_per_second));
      format_bytes(received_rate, received_per_second,
                   sizeof(received_per_second));
      if (stats.local_address[0] &&
          strcmp(stats.interface_name, stats.local_address) != 0)
        snprintf(label, sizeof(label), "%s (%s)", stats.interface_name,
                 stats.local_address);
      else
        snprintf(label, sizeof(label), "%s", stats.interface_name);
      fprintf(stderr,
              "qlinq-app: pv %s tx %s %" PRIu64 ":%02" PRIu64 ":%02" PRIu64
              " [%s/s] rx %s [%s/s]\n",
              label, sent_total, elapsed_seconds / 3600U,
              (elapsed_seconds / 60U) % 60U, elapsed_seconds % 60U,
              sent_per_second, received_total, received_per_second);

      previous->interface_index = stats.interface_index;
      memcpy(previous->local_address, stats.local_address,
             sizeof(previous->local_address));
      previous->bytes_sent = stats.bytes_sent;
      previous->bytes_received = stats.bytes_received;
      previous->initialized = true;
    }
  }
  app->pv_last_at = now;
  app->next_pv_at = now + APP_PV_INTERVAL_MS;
}

static void drive(app_ctx_t *app) {
  for (size_t i = 0; i < app->num_transports; i++)
    if (app->transports[i].transport)
      transport_tick(app->transports[i].transport);
  int64_t now = transport_get_time_ms();
  for (size_t i = 0; i < app->num_transports; i++) {
    app_transport_t *entry = &app->transports[i];
    if (entry->is_server || !entry->reconnect_pending ||
        now < entry->next_reconnect_at)
      continue;
    if (entry->transport) {
      transport_destroy(entry->transport);
      entry->transport = NULL;
    }
    entry->reconnect_pending = false;
    entry->transport = transport_create(&entry->config);
    if (!entry->transport) {
      entry->reconnect_pending = true;
      entry->next_reconnect_at = now + app->reconnect_ms;
    } else if (app->verbose) {
      fprintf(stderr, "qlinq-app: reconnecting to peer\n");
    }
  }
  load_input(app, now);
  publish_pending(app, now);
  finish_input_track(app, now);
  if (app->leave_after_ms != 0 && !app->receive_unsubscribed) {
    if (app->membership_joined_at == 0 &&
        active_receive_memberships(app) != 0)
      app->membership_joined_at = now;
    if (app->membership_joined_at != 0 &&
        now - app->membership_joined_at >= app->leave_after_ms)
      (void)unsubscribe_receivers(app, now);
  }
  if (app->receive_done_at != 0 && !app->receive_unsubscribed &&
      receive_track_end_observed(app)) {
    (void)unsubscribe_receivers(app, now);
  }
  print_stats(app, now, false);
  print_pv(app, now, false);
}

int main(int argc, char **argv) {
  const char *bind_host = "0.0.0.0", *cert_file = "t/assets/server.crt";
  const char *key_file = "t/assets/server.key", *ca_file = NULL;
  const char *input_path = NULL, *output_path = NULL;
  const char *stats_path = NULL, *repair_shadow_path = NULL;
  const char *flexicast_group = NULL, *flexicast_interface = NULL;
  const char *peer_args[APP_MAX_TRANSPORTS];
  size_t num_peers = 0, message_size = 1200, max_connections = 0;
  size_t max_repair_requests = 0, max_aggregate_repairs = 0;
  uint64_t parsed = 0, startup_rate = 0, minimum_rate = 0, maximum_rate = 0;
  uint64_t aggregate_rate = 0, feedback_timeout = 0, repair_feedback_seed = 0;
  uint64_t idle_timeout = 0;
  uint64_t repair_shadow_deadline = 0;
  uint16_t listen_port = 0, flexicast_port = 0;
  bool verify_peer = true, allow_insecure = false, flexicast = false;
  uint8_t simulated_loss_rate = 0;
  transport_flexicast_cc_mode_t cc_mode = TRANSPORT_FLEXICAST_CC_MULTICAST;
  transport_flexicast_repair_route_t repair_route =
      TRANSPORT_FLEXICAST_REPAIR_SHARED;
  transport_repair_mode_t repair_mode = TRANSPORT_REPAIR_MODE_AUTO;
  app_ctx_t app = {0};
  app.track.type = MOQ_TRACK_DATA;
  app.track.flags = MOQ_TRACK_FLAG_FEC_ENABLED;
  strcpy(app.track.name, "qlinq-app/data");
  app.drain_ms = 1000;
  app.reconnect_ms = APP_DEFAULT_RECONNECT_MS;
  app.node_id = "node";
  app.required_subscriptions = 1;

  for (int i = 1; i < argc; i++) {
#define REQUIRE_VALUE()                                                        \
  do {                                                                         \
    if (++i >= argc) {                                                         \
      fprintf(stderr, "qlinq-app: %s requires a value\n", argv[i - 1]);        \
      return 1;                                                                \
    }                                                                          \
  } while (0)
    if (strcmp(argv[i], "--help") == 0) {
      show_help(stdout, argv[0]);
      return 0;
    } else if (strcmp(argv[i], "--listen") == 0) {
      REQUIRE_VALUE();
      if (!parse_u64(argv[i], UINT16_MAX, &parsed) || parsed == 0)
        goto Invalid;
      listen_port = (uint16_t)parsed;
    } else if (strcmp(argv[i], "--peer") == 0) {
      REQUIRE_VALUE();
      if (num_peers == APP_MAX_TRANSPORTS)
        goto Invalid;
      peer_args[num_peers++] = argv[i];
    } else if (strcmp(argv[i], "--bind") == 0) {
      REQUIRE_VALUE();
      bind_host = argv[i];
    } else if (strcmp(argv[i], "--reconnect-ms") == 0) {
      REQUIRE_VALUE();
      if (!parse_u64(argv[i], UINT32_MAX, &parsed))
        goto Invalid;
      app.reconnect_ms = (uint32_t)parsed;
    } else if (strcmp(argv[i], "--start-delay-ms") == 0) {
      REQUIRE_VALUE();
      if (!parse_u64(argv[i], UINT32_MAX, &parsed))
        goto Invalid;
      app.start_delay_ms = (uint32_t)parsed;
    } else if (strcmp(argv[i], "--idle-timeout-ms") == 0) {
      REQUIRE_VALUE();
      if (!parse_u64(argv[i], UINT64_MAX, &idle_timeout) || idle_timeout == 0)
        goto Invalid;
    } else if (strcmp(argv[i], "--cert") == 0) {
      REQUIRE_VALUE();
      cert_file = argv[i];
    } else if (strcmp(argv[i], "--key") == 0) {
      REQUIRE_VALUE();
      key_file = argv[i];
    } else if (strcmp(argv[i], "--ca") == 0) {
      REQUIRE_VALUE();
      ca_file = argv[i];
    } else if (strcmp(argv[i], "--auth-token") == 0) {
      REQUIRE_VALUE();
      app.auth_token = (const uint8_t *)argv[i];
    } else if (strcmp(argv[i], "--insecure-no-verify") == 0) {
      verify_peer = false;
      allow_insecure = true;
    } else if (strcmp(argv[i], "--max-connections") == 0) {
      REQUIRE_VALUE();
      if (!cli_parse_u64(argv[i], TRANSPORT_HARD_MAX_CONNECTIONS, &parsed) ||
          parsed == 0)
        goto Invalid;
      max_connections = (size_t)parsed;
    } else if (strcmp(argv[i], "--max-repair-requests") == 0) {
      REQUIRE_VALUE();
      if (!parse_u64(argv[i], UINT16_MAX, &parsed) || parsed == 0)
        goto Invalid;
      max_repair_requests = (size_t)parsed;
    } else if (strcmp(argv[i], "--max-aggregate-repairs") == 0) {
      REQUIRE_VALUE();
      if (!parse_u64(argv[i], UINT16_MAX, &parsed) || parsed == 0)
        goto Invalid;
      max_aggregate_repairs = (size_t)parsed;
    } else if (strcmp(argv[i], "--repair-feedback-seed") == 0) {
      REQUIRE_VALUE();
      if (!parse_u64(argv[i], UINT64_MAX, &repair_feedback_seed))
        goto Invalid;
    } else if (strcmp(argv[i], "--repair-shadow-file") == 0) {
      REQUIRE_VALUE();
      repair_shadow_path = argv[i];
    } else if (strcmp(argv[i], "--repair-shadow-deadline") == 0) {
      REQUIRE_VALUE();
      if (!parse_u64(argv[i], UINT64_MAX, &repair_shadow_deadline) ||
          repair_shadow_deadline == 0)
        goto Invalid;
    } else if (strcmp(argv[i], "--loss") == 0) {
      REQUIRE_VALUE();
      if (!parse_u64(argv[i], 100, &parsed))
        goto Invalid;
      simulated_loss_rate = (uint8_t)parsed;
    } else if (strcmp(argv[i], "--track") == 0) {
      REQUIRE_VALUE();
      if (strlen(argv[i]) >= sizeof(app.track.name))
        goto Invalid;
      strcpy(app.track.name, argv[i]);
    } else if (strcmp(argv[i], "--mode") == 0) {
      REQUIRE_VALUE();
      if (strcmp(argv[i], "datagram") == 0)
        app.track.flags = 0;
      else if (strcmp(argv[i], "fec") == 0)
        app.track.flags = MOQ_TRACK_FLAG_FEC_ENABLED;
      else if (strcmp(argv[i], "rateless") == 0)
        app.track.flags = MOQ_TRACK_FLAG_FEC_RATELESS;
      else if (strcmp(argv[i], "reliable") == 0)
        app.track.flags = MOQ_TRACK_FLAG_RELIABLE;
      else
        goto Invalid;
    } else if (strcmp(argv[i], "--repair-mode") == 0) {
      REQUIRE_VALUE();
      if (strcmp(argv[i], "auto") == 0)
        repair_mode = TRANSPORT_REPAIR_MODE_AUTO;
      else if (strcmp(argv[i], "indexed") == 0)
        repair_mode = TRANSPORT_REPAIR_MODE_INDEXED;
      else if (strcmp(argv[i], "rateless") == 0)
        repair_mode = TRANSPORT_REPAIR_MODE_RATELESS;
      else
        goto Invalid;
    } else if (strcmp(argv[i], "--input") == 0) {
      REQUIRE_VALUE();
      input_path = argv[i];
    } else if (strcmp(argv[i], "--output") == 0) {
      REQUIRE_VALUE();
      output_path = argv[i];
    } else if (strcmp(argv[i], "--message-size") == 0) {
      REQUIRE_VALUE();
      if (!parse_u64(argv[i], APP_MAX_MESSAGE_SIZE, &parsed) || parsed == 0)
        goto Invalid;
      message_size = (size_t)parsed;
    } else if (strcmp(argv[i], "--count") == 0) {
      REQUIRE_VALUE();
      if (!parse_u64(argv[i], UINT64_MAX, &app.count_limit))
        goto Invalid;
    } else if (strcmp(argv[i], "--receive-count") == 0) {
      REQUIRE_VALUE();
      if (!cli_parse_u64(argv[i], UINT64_MAX, &app.receive_limit) ||
          app.receive_limit == 0)
        goto Invalid;
    } else if (strcmp(argv[i], "--leave-after-ms") == 0) {
      REQUIRE_VALUE();
      if (!parse_u64(argv[i], UINT32_MAX, &parsed) || parsed == 0)
        goto Invalid;
      app.leave_after_ms = (uint32_t)parsed;
    } else if (strcmp(argv[i], "--late-join") == 0) {
      app.late_join = true;
    } else if (strcmp(argv[i], "--wait-subscribers") == 0) {
      REQUIRE_VALUE();
      if (!parse_u64(argv[i], SIZE_MAX, &parsed) || parsed == 0)
        goto Invalid;
      app.required_subscriptions = (size_t)parsed;
    } else if (strcmp(argv[i], "--wait-members") == 0) {
      REQUIRE_VALUE();
      if (!parse_u64(argv[i], SIZE_MAX, &parsed) || parsed == 0)
        goto Invalid;
      app.required_flexicast_members = (size_t)parsed;
      flexicast = true;
    } else if (strcmp(argv[i], "--interval-ms") == 0) {
      REQUIRE_VALUE();
      if (!parse_u64(argv[i], UINT32_MAX, &parsed))
        goto Invalid;
      app.interval_ms = (uint32_t)parsed;
    } else if (strcmp(argv[i], "--one-shot") == 0) {
      app.one_shot = true;
    } else if (strcmp(argv[i], "--drain-ms") == 0) {
      REQUIRE_VALUE();
      if (!parse_u64(argv[i], UINT32_MAX, &parsed))
        goto Invalid;
      app.drain_ms = (uint32_t)parsed;
    } else if (strcmp(argv[i], "--stats-ms") == 0) {
      REQUIRE_VALUE();
      if (!parse_u64(argv[i], UINT32_MAX, &parsed))
        goto Invalid;
      app.stats_ms = (uint32_t)parsed;
    } else if (strcmp(argv[i], "--stats-file") == 0) {
      REQUIRE_VALUE();
      stats_path = argv[i];
    } else if (strcmp(argv[i], "--pv") == 0) {
      app.pv = true;
    } else if (strcmp(argv[i], "--node-id") == 0) {
      REQUIRE_VALUE();
      if (argv[i][0] == '\0' || strchr(argv[i], '\t') || strchr(argv[i], '\n'))
        goto Invalid;
      app.node_id = argv[i];
    } else if (strcmp(argv[i], "--verbose") == 0) {
      app.verbose = true;
    } else if (strcmp(argv[i], "--flexicast") == 0) {
      flexicast = true;
    } else if (strcmp(argv[i], "--flexicast-group") == 0) {
      REQUIRE_VALUE();
      flexicast_group = argv[i];
      flexicast = true;
    } else if (strcmp(argv[i], "--flexicast-port") == 0) {
      REQUIRE_VALUE();
      if (!parse_u64(argv[i], UINT16_MAX, &parsed) || parsed == 0)
        goto Invalid;
      flexicast_port = (uint16_t)parsed;
    } else if (strcmp(argv[i], "--flexicast-interface") == 0) {
      REQUIRE_VALUE();
      flexicast_interface = argv[i];
    } else if (strcmp(argv[i], "--flexicast-cc") == 0) {
      REQUIRE_VALUE();
      if (strcmp(argv[i], "adaptive") == 0)
        cc_mode = TRANSPORT_FLEXICAST_CC_ADAPTIVE;
      else if (strcmp(argv[i], "multicast") != 0)
        goto Invalid;
      flexicast = true;
    } else if (strcmp(argv[i], "--flexicast-repair-route") == 0) {
      REQUIRE_VALUE();
      if (strcmp(argv[i], "shared") == 0)
        repair_route = TRANSPORT_FLEXICAST_REPAIR_SHARED;
      else if (strcmp(argv[i], "unicast") == 0)
        repair_route = TRANSPORT_FLEXICAST_REPAIR_UNICAST;
      else
        goto Invalid;
      flexicast = true;
    } else if (strcmp(argv[i], "--flexicast-cc-startup-rate") == 0) {
      REQUIRE_VALUE();
      if (!parse_u64(argv[i], UINT64_MAX, &startup_rate))
        goto Invalid;
      flexicast = true;
    } else if (strcmp(argv[i], "--flexicast-cc-min-rate") == 0) {
      REQUIRE_VALUE();
      if (!parse_u64(argv[i], UINT64_MAX, &minimum_rate))
        goto Invalid;
      flexicast = true;
    } else if (strcmp(argv[i], "--flexicast-cc-max-rate") == 0) {
      REQUIRE_VALUE();
      if (!parse_u64(argv[i], UINT64_MAX, &maximum_rate))
        goto Invalid;
      flexicast = true;
    } else if (strcmp(argv[i], "--flexicast-cc-aggregate-rate") == 0) {
      REQUIRE_VALUE();
      if (!parse_u64(argv[i], UINT64_MAX, &aggregate_rate))
        goto Invalid;
      flexicast = true;
    } else if (strcmp(argv[i], "--flexicast-cc-feedback-timeout") == 0) {
      REQUIRE_VALUE();
      if (!parse_u64(argv[i], UINT32_MAX, &feedback_timeout))
        goto Invalid;
      flexicast = true;
    } else {
      goto Invalid;
    }
#undef REQUIRE_VALUE
  }

  if ((listen_port == 0 && num_peers == 0) ||
      (listen_port != 0 && num_peers == APP_MAX_TRANSPORTS) ||
      (!input_path && !output_path) || (app.one_shot && !input_path) ||
      (app.leave_after_ms != 0 &&
       (num_peers == 0 || app.receive_limit != 0)) ||
      !app.auth_token || app.auth_token[0] == '\0' ||
      (flexicast_group && (!flexicast_port || !flexicast_interface)) ||
      (!flexicast_group && flexicast_port != 0))
    goto Invalid;
  app.auth_token_len = strlen((const char *)app.auth_token);
  if (app.auth_token_len > UINT16_MAX)
    goto Invalid;

  if (input_path) {
    app.input = strcmp(input_path, "-") == 0 ? stdin : fopen(input_path, "rb");
    if (!app.input) {
      fprintf(stderr, "qlinq-app: unable to open input '%s': %s\n", input_path,
              strerror(errno));
      goto Cleanup;
    }
  }
  if (output_path) {
    app.output =
        strcmp(output_path, "-") == 0 ? stdout : fopen(output_path, "wb");
    if (!app.output) {
      fprintf(stderr, "qlinq-app: unable to open output '%s': %s\n",
              output_path, strerror(errno));
      goto Cleanup;
    }
  }
  if (stats_path) {
    app.stats_output = fopen(stats_path, "w");
    if (!app.stats_output) {
      fprintf(stderr, "qlinq-app: unable to open stats file '%s': %s\n",
              stats_path, strerror(errno));
      goto Cleanup;
    }
    fprintf(app.stats_output,
            "elapsed_ms\tnode\ttx_objects\trx_objects\trx_bytes\t"
            "flexicast_packets\tacks\trepair_requests\trepair_symbols\t"
            "duplicates\tactive_members\tqueued_packets\tsubscriptions\t"
            "cc_rate_Bps\ttrack_ends_sent\ttrack_ends_received\t"
            "repair_requests_deferred\trecovery_checkpoints_sent\t"
            "recovery_checkpoints_received\t"
            "recovery_checkpoint_acks_sent\t"
            "recovery_checkpoint_acks_received\trecovery_cache_releases\t"
            "recovery_cache_backpressure\trepair_multicast_symbols\t"
            "repair_requests_suppressed\t"
            "repair_requests_aggregate_throttled\t"
            "repair_requests_merged\trepair_batches_emitted\t"
            "repair_queue_backpressure\trepair_physical_bytes\t"
            "flexicast_physical_bytes\trepair_queued_packets\t"
            "repair_queued_bytes\trepair_pending_objects\t"
            "repair_oldest_age_ms\trepair_packets_cancelled\t"
            "repair_pending_symbols_cancelled\t"
            "flexicast_feedback_fallbacks\t"
            "repair_indexed_requests_sent\t"
            "repair_rateless_requests_sent\t"
            "repair_indexed_requests_received\t"
            "repair_rateless_requests_received\t"
            "repair_rateless_symbols_sent\t"
            "repair_rateless_exhausted\t"
            "repair_requester_records_peak\t"
            "repair_requester_overflow\t"
            "repair_requester_updates\t"
            "repair_requester_records_expired\t"
            "cc_rate_increase_events\tcc_rate_reduction_events\t"
            "cc_floor_entry_events\tcc_floor_exit_events\t"
            "cc_ack_growth_events\tcc_other_growth_events\t"
            "cc_loss_reduction_events\tcc_rtt_reduction_events\t"
            "cc_ecn_reduction_events\tcc_timeout_reduction_events\t"
            "cc_rate_limit_reduction_events\tcc_other_reduction_events\t"
            "cc_external_load_growth_freeze_events\t"
            "sample_epoch_ms\ttrack_finished_epoch_ms\t"
            "receive_done_epoch_ms\t"
            "repair_shadow_plans\trepair_shadow_all_shared\t"
            "repair_shadow_all_unicast\trepair_shadow_mixed\t"
            "repair_shadow_uncertain\trepair_shadow_infeasible\t"
            "repair_shadow_log_errors\trepair_shadow_last_airtime_us\t"
            "repair_shadow_last_physical_bytes\t"
            "repair_shadow_last_savings_ppm\t"
            "repair_shadow_observation_overflow\t"
            "repair_unicast_symbols\trepair_unicast_payload_bytes\t"
            "recovery_checkpoints_pending\t"
            "recovery_oldest_checkpoint_age_ms\tflexicast_rekeys\t"
            "flexicast_rekey_members\tflexicast_rekey_batched_changes\t"
            "flexicast_membership_joins\tflexicast_membership_leaves\t"
            "flexicast_fallbacks\tactive_connections\t"
            "assembler_memory_bytes\tegress_peak_packets\t"
            "egress_peak_bytes\tactive_flows\tactive_memberships\n");
  }
  if (!(app.message = malloc(message_size))) {
    fprintf(stderr, "qlinq-app: unable to allocate input buffer\n");
    goto Cleanup;
  }
  app.message_capacity = message_size;

  if (portable_socket_init() != 0) {
    fprintf(stderr, "qlinq-app: socket initialization failed\n");
    goto Cleanup;
  }
  signal(SIGINT, handle_signal);
  signal(SIGTERM, handle_signal);

#define APPLY_COMMON_CONFIG(config_)                                           \
  do {                                                                         \
    (config_).cert_file = cert_file;                                           \
    (config_).key_file = key_file;                                             \
    (config_).ca_file = ca_file;                                               \
    (config_).verify_peer = verify_peer;                                       \
    (config_).allow_insecure_peer = allow_insecure;                            \
    (config_).quic_idle_timeout_ms = idle_timeout;                            \
    (config_).simulated_loss_rate = simulated_loss_rate;                       \
    (config_).limits.max_connections = max_connections;                        \
    (config_).limits.max_repair_requests_per_second = max_repair_requests;     \
    (config_).limits.max_aggregate_repair_requests_per_second =                \
        max_aggregate_repairs;                                                 \
    (config_).repair_mode = repair_mode;                                       \
    (config_).repair_feedback_seed = repair_feedback_seed;                     \
    (config_).repair_shadow_deadline_ms = repair_shadow_deadline;              \
    (config_).enable_flexicast = flexicast;                                    \
    (config_).flexicast_interface = flexicast_interface;                       \
    (config_).flexicast_cc_mode = cc_mode;                                     \
    (config_).flexicast_repair_route = repair_route;                           \
    (config_).flexicast_cc_startup_rate = startup_rate;                        \
    (config_).flexicast_cc_minimum_rate = minimum_rate;                        \
    (config_).flexicast_cc_maximum_rate = maximum_rate;                        \
    (config_).flexicast_cc_aggregate_rate_limit = aggregate_rate;              \
    (config_).flexicast_cc_feedback_timeout_ms = (uint32_t)feedback_timeout;   \
  } while (0)

  if (listen_port != 0) {
    app_transport_t *entry = &app.transports[app.num_transports];
    transport_config_t config = {0};
    APPLY_COMMON_CONFIG(config);
    config.bind_hosts[config.num_bind_hosts++] = bind_host;
    config.port = listen_port;
    config.flexicast_group = flexicast_group;
    config.flexicast_group_port = flexicast_port;
    config.repair_shadow_log_file = repair_shadow_path;
    config.callback = on_transport_event;
    config.user_data = entry;
    entry->app = &app;
    entry->is_server = true;
    entry->config = config;
    if (!(entry->transport = transport_create(&entry->config))) {
      fprintf(stderr, "qlinq-app: unable to create listener\n");
      goto CleanupSockets;
    }
    app.num_transports++;
  }
  for (size_t i = 0; i < num_peers; i++) {
    app_transport_t *entry = &app.transports[app.num_transports];
    transport_config_t config = {0};
    uint16_t port = 8888;
    if (!parse_peer(peer_args[i], entry->remote_host,
                    sizeof(entry->remote_host), &port)) {
      fprintf(stderr, "qlinq-app: invalid peer '%s'\n", peer_args[i]);
      goto CleanupSockets;
    }
    APPLY_COMMON_CONFIG(config);
    config.bind_hosts[config.num_bind_hosts++] =
        strchr(entry->remote_host, ':') ? "::" : "0.0.0.0";
    config.remote_hosts[config.num_remote_hosts++] = entry->remote_host;
    config.port = port;
    config.callback = on_transport_event;
    config.user_data = entry;
    entry->app = &app;
    entry->config = config;
    if (!(entry->transport = transport_create(&entry->config))) {
      fprintf(stderr, "qlinq-app: unable to connect to '%s'\n", peer_args[i]);
      goto CleanupSockets;
    }
    app.num_transports++;
  }
#undef APPLY_COMMON_CONFIG

  app.started_at = transport_get_time_ms();
  app.next_stats_at = app.started_at + app.stats_ms;
  app.pv_last_at = app.started_at;
  app.next_pv_at = app.started_at + APP_PV_INTERVAL_MS;
  while (app_running && !app.failed) {
    drive(&app);
    int64_t now = transport_get_time_ms();
    bool send_done = !app.one_shot ||
                     (app.input_eof && app.pending_size == 0 &&
                      app.track_finished && now - app.eof_at >= app.drain_ms);
    int64_t receive_drain_started_at =
        (app.track.flags & MOQ_TRACK_FLAG_FEC_RATELESS) != 0
            ? app.receive_unsubscribed_at
            : app.receive_done_at;
    bool receive_done =
        (app.receive_limit == 0 && app.leave_after_ms == 0) ||
        (receive_drain_started_at != 0 &&
         now - receive_drain_started_at >= app.drain_ms);
    if ((app.one_shot || app.receive_limit != 0 || app.leave_after_ms != 0) &&
        send_done && receive_done)
      break;
    struct pollfd fds[APP_MAX_TRANSPORTS * (TRANSPORT_MAX_PATHS + 2)];
    size_t num_fds = 0;
    int timeout = 10;
    for (size_t i = 0; i < app.num_transports; i++) {
      if (!app.transports[i].transport)
        continue;
      int64_t deadline =
          transport_get_first_timeout(app.transports[i].transport);
      if (deadline != INT64_MAX && deadline <= now)
        timeout = 0;
      else if (deadline != INT64_MAX && deadline - now < timeout)
        timeout = (int)(deadline - now);
      num_fds +=
          transport_get_poll_fds(app.transports[i].transport, fds + num_fds,
                                 sizeof(fds) / sizeof(fds[0]) - num_fds);
    }
    size_t input_fd_index = SIZE_MAX;
    if (app.pending_size == 0 && app.input && !app.input_eof &&
        transports_ready(&app) && app.next_send_at <= now) {
      int fd = fileno(app.input);
      if (fd >= 0 && num_fds < sizeof(fds) / sizeof(fds[0])) {
        input_fd_index = num_fds;
        fds[num_fds++] = (struct pollfd){.fd = fd, .events = POLLIN};
      }
    }
    if (num_fds != 0) {
      if (poll(fds, num_fds, timeout) > 0 && input_fd_index != SIZE_MAX &&
          (fds[input_fd_index].revents & (POLLIN | POLLHUP)) != 0)
        app.input_ready = true;
    } else if (timeout != 0) {
      usleep((useconds_t)timeout * 1000);
    }
  }
  int64_t stopped_at = transport_get_time_ms();
  print_stats(&app, stopped_at, true);
  print_pv(&app, stopped_at, true);

CleanupSockets:
  for (size_t i = 0; i < app.num_transports; i++)
    if (app.transports[i].transport)
      transport_destroy(app.transports[i].transport);
  portable_socket_cleanup();
Cleanup:
  reset_reorder(&app);
  free(app.message);
  if (app.input && app.input != stdin)
    fclose(app.input);
  if (app.output && app.output != stdout)
    fclose(app.output);
  if (app.stats_output)
    fclose(app.stats_output);
  return app.failed ? 1 : 0;

Invalid:
  fprintf(stderr, "qlinq-app: invalid command line\n");
  show_help(stderr, argv[0]);
  return 1;
}
