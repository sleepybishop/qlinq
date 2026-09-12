#include "transport_protocol.h"

#include "fec.h"
#include "transport_publish.h"
#include "transport_repair.h"
#include "transport_stream.h"
#include "transport_wire.h"

#include "quicly/sendstate.h"
#include "quicly/streambuf.h"

#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool transport_track_type_valid(uint8_t type) {
  return type == MOQ_TRACK_VIDEO || type == MOQ_TRACK_AUDIO ||
         type == MOQ_TRACK_INPUT || type == MOQ_TRACK_TEXT ||
         type == MOQ_TRACK_DATA || type == MOQ_TRACK_TELEMETRY;
}

static uint32_t local_capabilities(void) {
  return QLINQ_WIRE_CAP_RELIABLE | QLINQ_WIRE_CAP_DATAGRAM |
         QLINQ_WIRE_CAP_FEC_REED_SOLOMON | QLINQ_WIRE_CAP_FEC_RATELESS |
         QLINQ_WIRE_CAP_MULTIPATH | QLINQ_WIRE_CAP_AUTHENTICATION |
         QLINQ_WIRE_CAP_RATELESS_REPAIR | QLINQ_WIRE_CAP_RECOVERY_CHECKPOINTS;
}

bool transport_protocol_send_hello(transport_conn_t *conn) {
  if (!conn || conn->hello_sent || !conn->stream ||
      !quicly_sendstate_is_open(&conn->stream->sendstate))
    return conn && conn->hello_sent;
  transport_t *t = conn->transport;
  size_t datagram_size = t->limits.max_udp_payload_size;
  if (datagram_size > UINT16_MAX)
    datagram_size = UINT16_MAX;
  qlinq_wire_hello_t hello = {
      .role = t->is_server ? QLINQ_WIRE_ROLE_SERVER : QLINQ_WIRE_ROLE_CLIENT,
      .max_paths = (uint16_t)t->num_fds,
      .capabilities = local_capabilities(),
      .max_reliable_object_size = (uint32_t)t->limits.max_reliable_object_size,
      .max_fec_object_size = (uint32_t)t->limits.max_fec_object_size,
      .max_subscriptions = (uint16_t)t->limits.max_subscriptions_per_connection,
      .max_datagram_size = (uint16_t)datagram_size};
  uint8_t payload[QLINQ_WIRE_HELLO_SIZE];
  if (qlinq_wire_encode_hello(payload, sizeof(payload), &hello) !=
          QLINQ_WIRE_OK ||
      !transport_stream_write_frame(conn->stream, QLINQ_WIRE_HELLO, payload,
                                    sizeof(payload)))
    return false;
  conn->hello_sent = true;
  return true;
}

void transport_protocol_maybe_emit_connected(transport_conn_t *conn) {
  if (!conn || conn->connected_emitted || !conn->quic_ready ||
      !conn->protocol_ready)
    return;
  conn->connected_emitted = true;
  transport_t *t = conn->transport;
  t->stats.protocol_handshakes_completed++;
  if (t->reconnect_in_progress) {
    t->stats.reconnect_succeeded++;
    t->reconnect_in_progress = false;
    t->reconnect_current_delay_ms = t->reconnect_initial_delay_ms;
    transport_log(t, TRANSPORT_LOG_INFO, "connection", conn->id, SIZE_MAX,
                  "reconnect completed");
  }
  transport_event_t event = {.type = TRANSPORT_EVENT_CONNECTED, .conn = conn};
  transport_emit_event(t, &event);
}

static bool receive_hello(transport_conn_t *conn, const uint8_t *payload,
                          size_t payload_len) {
  if (!conn || conn->hello_received)
    return false;
  qlinq_wire_hello_t hello;
  if (qlinq_wire_decode_hello(payload, payload_len, &hello) != QLINQ_WIRE_OK)
    return false;
  transport_t *t = conn->transport;
  uint8_t expected_role =
      t->is_server ? QLINQ_WIRE_ROLE_CLIENT : QLINQ_WIRE_ROLE_SERVER;
  uint32_t required = QLINQ_WIRE_CAP_RELIABLE | QLINQ_WIRE_CAP_DATAGRAM;
  if (hello.role != expected_role ||
      (hello.capabilities & required) != required)
    return false;

  conn->peer_capabilities = hello.capabilities;
  conn->negotiated_limits = t->limits;
  if (conn->negotiated_limits.max_reliable_object_size >
      hello.max_reliable_object_size)
    conn->negotiated_limits.max_reliable_object_size =
        hello.max_reliable_object_size;
  if (conn->negotiated_limits.max_fec_object_size > hello.max_fec_object_size)
    conn->negotiated_limits.max_fec_object_size = hello.max_fec_object_size;
  if (conn->negotiated_limits.max_subscriptions_per_connection >
      hello.max_subscriptions)
    conn->negotiated_limits.max_subscriptions_per_connection =
        hello.max_subscriptions;
  if (conn->negotiated_limits.max_udp_payload_size > hello.max_datagram_size)
    conn->negotiated_limits.max_udp_payload_size = hello.max_datagram_size;
  conn->hello_received = true;
  if (!transport_protocol_send_hello(conn))
    return false;
  conn->protocol_ready = true;
  transport_protocol_maybe_emit_connected(conn);
  return true;
}

static void close_wire_error(transport_conn_t *conn,
                             qlinq_wire_result_t result) {
  const char *reason = result == QLINQ_WIRE_UNSUPPORTED_VERSION
                           ? "protocol version mismatch"
                           : "protocol error: malformed frame";
  conn->transport->stats.protocol_errors++;
  quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL, reason);
}

static bool repair_request_allowed(transport_conn_t *conn) {
  int64_t now = transport_get_time_ms();
  conn->transport->stats.repair_requests_received++;
  if (!transport_repair_limiter_take(
          &conn->repair_request_limiter,
          conn->transport->limits.max_repair_requests_per_second, now)) {
    conn->transport->stats.repair_requests_throttled++;
    return false;
  }
  return true;
}

static bool object_was_delivered(const transport_object_gap_state_t *state,
                                 uint64_t object_id) {
  if (!state->delivered_initialized || object_id > state->largest_delivered)
    return false;
  uint64_t distance = state->largest_delivered - object_id;
  if (distance >= QLINQ_RECOVERY_HISTORY_OBJECTS)
    return true;
  return (state->delivered_mask[distance / 64U] &
          (UINT64_C(1) << (distance % 64U))) != 0;
}

static bool
object_is_recently_delivered(const transport_object_gap_state_t *state,
                             uint64_t object_id) {
  if (!state->delivered_initialized || object_id > state->largest_delivered)
    return false;
  uint64_t distance = state->largest_delivered - object_id;
  return distance < QLINQ_RECOVERY_HISTORY_OBJECTS &&
         (state->delivered_mask[distance / 64U] &
          (UINT64_C(1) << (distance % 64U))) != 0;
}

static void mark_object_delivered(transport_object_gap_state_t *state,
                                  uint64_t object_id) {
  if (!state->delivered_initialized) {
    state->delivered_initialized = true;
    state->largest_delivered = object_id;
    state->delivered_mask[0] = 1;
    return;
  }
  if (object_id > state->largest_delivered) {
    uint64_t distance = object_id - state->largest_delivered;
    uint64_t shifted[QLINQ_RECOVERY_HISTORY_OBJECTS / 64U] = {0};
    if (distance < QLINQ_RECOVERY_HISTORY_OBJECTS) {
      size_t word_shift = (size_t)(distance / 64U);
      unsigned bit_shift = (unsigned)(distance % 64U);
      for (size_t dst = QLINQ_RECOVERY_HISTORY_OBJECTS / 64U; dst-- > 0;) {
        if (dst < word_shift)
          continue;
        size_t src = dst - word_shift;
        shifted[dst] = state->delivered_mask[src] << bit_shift;
        if (bit_shift != 0 && src > 0)
          shifted[dst] |= state->delivered_mask[src - 1U] >> (64U - bit_shift);
      }
    }
    memcpy(state->delivered_mask, shifted, sizeof(shifted));
    state->delivered_mask[0] |= 1;
    state->largest_delivered = object_id;
  } else {
    uint64_t distance = state->largest_delivered - object_id;
    if (distance < QLINQ_RECOVERY_HISTORY_OBJECTS)
      state->delivered_mask[distance / 64U] |= UINT64_C(1) << (distance % 64U);
  }
}

static bool send_checkpoint_ack(transport_conn_t *conn, uint8_t alias,
                                uint64_t group_id, uint64_t final_object_id) {
  if (!conn ||
      (conn->peer_capabilities & QLINQ_WIRE_CAP_RECOVERY_CHECKPOINTS) == 0 ||
      !conn->stream || !quicly_sendstate_is_open(&conn->stream->sendstate))
    return false;
  if (!transport_stream_write_track_checkpoint_ack_frame(
          conn->stream, alias, group_id, final_object_id))
    return false;
  conn->transport->stats.recovery_checkpoint_acks_sent++;
  return true;
}

static transport_recovery_window_t *
find_recovery_window(transport_object_gap_state_t *state, uint64_t group_id,
                     uint64_t first_object_id, uint64_t final_object_id) {
  for (size_t i = 0; i < QLINQ_RECOVERY_MAX_WINDOWS; i++) {
    transport_recovery_window_t *window = &state->recovery_windows[i];
    if (window->active && window->group_id == group_id &&
        window->first_object_id == first_object_id &&
        window->final_object_id == final_object_id)
      return window;
  }
  return NULL;
}

static void retire_recovery_through(transport_conn_t *conn, uint8_t alias,
                                    uint64_t group_id,
                                    uint64_t final_object_id) {
  if (!conn || !conn->transport)
    return;
  transport_t *t = conn->transport;
  transport_object_gap_state_t *gap = transport_object_gap(conn, alias);
  if (gap && gap->pending_mask != 0 && gap->group_id == group_id &&
      gap->pending_base <= final_object_id) {
    uint64_t distance = final_object_id - gap->pending_base;
    uint32_t covered = distance >= 31U
                           ? UINT32_MAX
                           : (UINT32_C(1) << (uint32_t)(distance + 1U)) - 1U;
    gap->pending_mask &= ~covered;
  }
  for (size_t i = 0; i < t->limits.max_assemblers_per_connection; i++) {
    frame_assembler_t *assembler = &conn->assemblers[i];
    if (assembler->total_symbols > 0 && assembler->track_id == alias &&
        assembler->group_id == group_id &&
        assembler->object_id <= final_object_id) {
      transport_release_assembler(t, assembler);
    }
  }
}

static bool acknowledge_completed_recovery_windows(transport_conn_t *conn,
                                                   uint8_t alias) {
  transport_object_gap_state_t *state = transport_object_gap(conn, alias);
  while (true) {
    transport_recovery_window_t *first = NULL;
    for (size_t i = 0; i < QLINQ_RECOVERY_MAX_WINDOWS; i++) {
      transport_recovery_window_t *window = &state->recovery_windows[i];
      if (!window->active ||
          (first && window->first_object_id >= first->first_object_id))
        continue;
      first = window;
    }
    if (!first || first->missing_mask != 0)
      return true;
    if (!send_checkpoint_ack(conn, alias, first->group_id,
                             first->final_object_id))
      return false;
    /* The cumulative ACK retires redundant gaps and partial duplicate objects
     * before the source releases its repair cache. */
    retire_recovery_through(conn, alias, first->group_id,
                            first->final_object_id);
    memset(first, 0, sizeof(*first));
  }
}

static bool receive_recovery_checkpoint(transport_conn_t *conn, uint8_t alias,
                                        uint64_t group_id,
                                        uint64_t first_object_id,
                                        uint64_t final_object_id,
                                        bool acknowledge) {
  if (!conn || first_object_id > final_object_id ||
      final_object_id - first_object_id >= QLINQ_RECOVERY_WINDOW_OBJECTS)
    return false;
  transport_object_gap_state_t *state = transport_object_gap(conn, alias);
  if (find_recovery_window(state, group_id, first_object_id, final_object_id))
    return true;

  if (state->checkpoint_initialized) {
    if (final_object_id <= state->last_checkpoint_object_id)
      return !acknowledge ||
             send_checkpoint_ack(conn, alias, group_id, final_object_id);
    if (state->last_checkpoint_object_id == UINT64_MAX ||
        first_object_id != state->last_checkpoint_object_id + 1U)
      return false;
  }

  transport_recovery_window_t *window = NULL;
  for (size_t i = 0; i < QLINQ_RECOVERY_MAX_WINDOWS; i++) {
    if (!state->recovery_windows[i].active) {
      window = &state->recovery_windows[i];
      break;
    }
  }
  if (!window)
    return false;

  memset(window, 0, sizeof(*window));
  window->group_id = group_id;
  window->first_object_id = first_object_id;
  window->final_object_id = final_object_id;
  window->last_request_ms = transport_get_time_ms();
  uint32_t count = (uint32_t)(final_object_id - first_object_id + 1U);
  for (uint32_t bit = 0; bit < count; bit++)
    if (!object_is_recently_delivered(state, first_object_id + bit))
      window->missing_mask |= 1U << bit;

  state->checkpoint_initialized = true;
  state->last_checkpoint_object_id = final_object_id;
  window->active = true;
  if (!acknowledge) {
    if (window->missing_mask == 0)
      memset(window, 0, sizeof(*window));
    return true;
  }
  return acknowledge_completed_recovery_windows(conn, alias);
}

static void recovery_mark_delivered(transport_conn_t *conn, uint8_t alias,
                                    uint64_t group_id, uint64_t object_id) {
  transport_object_gap_state_t *state = transport_object_gap(conn, alias);
  for (size_t i = 0; i < QLINQ_RECOVERY_MAX_WINDOWS; i++) {
    transport_recovery_window_t *window = &state->recovery_windows[i];
    if (!window->active || window->group_id != group_id ||
        object_id < window->first_object_id ||
        object_id > window->final_object_id)
      continue;
    window->missing_mask &=
        ~(1U << (uint32_t)(object_id - window->first_object_id));
  }
  (void)acknowledge_completed_recovery_windows(conn, alias);
}

static bool queue_missing_objects(transport_object_gap_state_t *state,
                                  uint64_t group_id, uint64_t first_missing,
                                  uint64_t missing_count) {
  if (!state || missing_count == 0)
    return true;
  if (missing_count > 32)
    return false;
  if (state->pending_mask == 0) {
    state->pending_base = first_missing;
    state->detected_at_ms = transport_get_time_ms();
    state->group_id = group_id;
  }
  if (first_missing < state->pending_base ||
      first_missing - state->pending_base >= 32)
    return false;
  uint32_t offset = (uint32_t)(first_missing - state->pending_base);
  uint32_t available = 32 - offset;
  uint32_t count =
      missing_count < available ? (uint32_t)missing_count : available;
  uint32_t bits = count == 32 ? UINT32_MAX : ((1U << count) - 1U);
  state->pending_mask |= bits << offset;
  return count == missing_count;
}

/* Parse complete, versioned control frames from the stream buffer. */
static void parse_control_messages(transport_t *t, transport_conn_t *conn,
                                   quicly_stream_t *stream) {
  while (1) {
    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);
    if (input.len == 0)
      break;

    qlinq_wire_frame_t frame;
    qlinq_wire_result_t result = qlinq_wire_decode_frame(
        input.base, input.len, TRANSPORT_WIRE_MAX_STREAM_PAYLOAD, &frame);
    if (result == QLINQ_WIRE_NEED_MORE)
      break;
    if (result != QLINQ_WIRE_OK) {
      close_wire_error(conn, result);
      break;
    }

    input = ptls_iovec_init(frame.payload, frame.payload_len);
    uint8_t type = frame.type;
    t->stats.stream_frames_received++;
    conn->stream_frames_received++;
    if (type != QLINQ_WIRE_HELLO && !conn->hello_received) {
      t->stats.protocol_errors++;
      quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL,
                   "protocol error: HELLO must be first");
      break;
    }
    if (type == QLINQ_WIRE_HELLO) {
      if (conn->stream_frames_received != 1 ||
          !receive_hello(conn, input.base, input.len)) {
        t->stats.protocol_errors++;
        quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL,
                     "protocol error: invalid HELLO");
        break;
      }
      quicly_streambuf_ingress_shift(stream, frame.consumed);
    } else if (type == QLINQ_WIRE_SUBSCRIBE || type == QLINQ_WIRE_UNSUBSCRIBE ||
               type == QLINQ_WIRE_KEYFRAME_REQUEST) {
      qlinq_wire_track_t wire_track;
      if (qlinq_wire_decode_track(input.base, input.len, &wire_track) !=
          QLINQ_WIRE_OK) {
        quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL,
                     "protocol error: invalid track");
        break;
      }

      if (!conn->authenticated) {
        quicly_close(conn->quic, TRANSPORT_APP_ERROR_AUTHENTICATION,
                     "unauthorized");
        break;
      }

      uint8_t alias = wire_track.alias;
      uint8_t track_type = wire_track.track_type;
      uint8_t flags = wire_track.flags;
      if (!transport_track_type_valid(track_type) ||
          (flags & ~(MOQ_TRACK_FLAG_RELIABLE | MOQ_TRACK_FLAG_FEC_ENABLED |
                     MOQ_TRACK_FLAG_FEC_RATELESS)) != 0) {
        quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL,
                     "protocol error: invalid track");
        break;
      }

      moq_track_id_t parsed_track = {.type = (moq_track_type_t)track_type,
                                     .flags = flags};
      strcpy(parsed_track.name, wire_track.name);

      if (type == QLINQ_WIRE_SUBSCRIBE) {
        moq_track_id_t aliased_track;
        if (transport_subscriptions_find_by_alias(&conn->send_subscriptions,
                                                  alias, &aliased_track) == 0 &&
            (aliased_track.type != parsed_track.type ||
             strcmp(aliased_track.name, parsed_track.name) != 0)) {
          t->stats.protocol_errors++;
          quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL,
                       "protocol error: track alias collision");
          break;
        }
        quicly_debug_printf(
            conn->quic,
            "Subscription mapping: track '%s' (type %d) mapped to alias %d",
            wire_track.name, track_type, alias);
        if (!transport_subscriptions_add(&conn->send_subscriptions,
                                         (moq_track_type_t)track_type, flags,
                                         wire_track.name, alias)) {
          t->stats.resource_limit_errors++;
          quicly_close(conn->quic, TRANSPORT_APP_ERROR_RESOURCE_LIMIT,
                       "protocol error: too many tracks");
          break;
        }
        transport_publish_checkpoint_member_added(t, conn, &parsed_track,
                                                  alias);
      } else if (type == QLINQ_WIRE_UNSUBSCRIBE) {
        transport_publish_checkpoint_member_removed(t, conn, &parsed_track,
                                                    alias);
        transport_subscriptions_remove(&conn->send_subscriptions,
                                       (moq_track_type_t)track_type,
                                       wire_track.name);
      }

      transport_event_type_t ev_type = TRANSPORT_EVENT_SUBSCRIBE;
      if (type == QLINQ_WIRE_UNSUBSCRIBE) {
        ev_type = TRANSPORT_EVENT_UNSUBSCRIBE;
      } else if (type == QLINQ_WIRE_KEYFRAME_REQUEST) {
        ev_type = TRANSPORT_EVENT_KEYFRAME_REQUEST;
      }

      transport_event_t ev = {
          .type = ev_type, .conn = conn, .track_id = parsed_track};
      transport_emit_event(t, &ev);
      quicly_streambuf_ingress_shift(stream, frame.consumed);
    } else if (type == QLINQ_WIRE_UNICAST) {
      size_t payload_size = input.len;
      if (payload_size > conn->negotiated_limits.max_reliable_object_size) {
        t->stats.resource_limit_errors++;
        quicly_close(conn->quic, TRANSPORT_APP_ERROR_RESOURCE_LIMIT,
                     "protocol error: payload too large");
        break;
      }

      if (!conn->authenticated) {
        quicly_close(conn->quic, TRANSPORT_APP_ERROR_AUTHENTICATION,
                     "unauthorized");
        break;
      }

      transport_event_t ev = {.type = TRANSPORT_EVENT_OBJECT,
                              .conn = conn,
                              .track_id = {.type = MOQ_TRACK_INPUT},
                              .object = {.track_id = {.type = MOQ_TRACK_INPUT},
                                         .group_id = 0,
                                         .object_id = 0,
                                         .data = input.base,
                                         .size = payload_size,
                                         .is_keyframe = false}};
      transport_emit_event(t, &ev);
      quicly_streambuf_ingress_shift(stream, frame.consumed);
    } else if (type == QLINQ_WIRE_AUTH_REQUEST) {
      size_t token_len = input.len;
      if (token_len > UINT16_MAX) {
        t->stats.resource_limit_errors++;
        quicly_close(conn->quic, TRANSPORT_APP_ERROR_RESOURCE_LIMIT,
                     "protocol error: auth token too large");
        break;
      }

      if (!t->is_server) {
        quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL,
                     "protocol error: unexpected auth request");
        break;
      }

      transport_event_t ev = {.type = TRANSPORT_EVENT_AUTH,
                              .conn = conn,
                              .auth = {.token = input.base,
                                       .token_len = token_len,
                                       .success = false}};
      transport_emit_event(t, &ev);
      quicly_streambuf_ingress_shift(stream, frame.consumed);
    } else if (type == QLINQ_WIRE_AUTH_RESPONSE) {
      if (input.len != 1 || input.base[0] > 1) {
        quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL,
                     "protocol error: invalid auth response");
        break;
      }

      if (t->is_server) {
        quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL,
                     "protocol error: unexpected auth response");
        break;
      }

      uint8_t status = input.base[0];
      if (status == 1) {
        conn->authenticated = true;
      }
      transport_event_t ev = {
          .type = TRANSPORT_EVENT_AUTH_COMPLETE,
          .conn = conn,
          .auth = {.token = NULL, .token_len = 0, .success = (status == 1)}};
      transport_emit_event(t, &ev);
      quicly_streambuf_ingress_shift(stream, frame.consumed);
    } else if (type == QLINQ_WIRE_TRACK_OBJECT) {
      quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL,
                   "protocol error: track object on control stream");
      break;
    } else if (type == QLINQ_WIRE_NACK) {
      qlinq_wire_nack_t nack;
      if (qlinq_wire_decode_nack(input.base, input.len, &nack) !=
          QLINQ_WIRE_OK) {
        quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL,
                     "protocol error: invalid nack");
        break;
      }

      if (!conn->authenticated) {
        quicly_close(conn->quic, TRANSPORT_APP_ERROR_AUTHENTICATION,
                     "unauthorized");
        break;
      }

      if (repair_request_allowed(conn)) {
        moq_track_id_t resolved_track;
        if (transport_subscriptions_find_by_alias(
                &conn->send_subscriptions, nack.alias, &resolved_track) == 0) {
          bool wire_rateless = (nack.flags & QLINQ_WIRE_NACK_RATELESS) != 0;
          if (wire_rateless &&
              ((resolved_track.flags & MOQ_TRACK_FLAG_FEC_RATELESS) == 0 ||
               (conn->peer_capabilities & QLINQ_WIRE_CAP_RATELESS_REPAIR) ==
                   0)) {
            quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL,
                         "protocol error: repair mode mismatch");
            break;
          }
          transport_repair_mode_t repair_mode =
              wire_rateless ? TRANSPORT_REPAIR_MODE_RATELESS
                            : TRANSPORT_REPAIR_MODE_INDEXED;
          if (wire_rateless)
            t->stats.repair_rateless_requests_received++;
          else
            t->stats.repair_indexed_requests_received++;
          sent_object_cache_t *cached = transport_sent_cache_find(
              &t->sent_cache, &resolved_track, nack.group_id, nack.object_id);
          if (cached) {
            uint16_t missing[TRANSPORT_REPAIR_MAX_SYMBOLS] = {0};
            size_t missing_count = nack.missing_count;
            if (missing_count > TRANSPORT_REPAIR_MAX_SYMBOLS)
              missing_count = TRANSPORT_REPAIR_MAX_SYMBOLS;
            bool indices_valid = true;
            if (repair_mode == TRANSPORT_REPAIR_MODE_INDEXED) {
              for (size_t i = 0; i < missing_count; i++) {
                if (!qlinq_wire_nack_index(&nack, i, &missing[i]) ||
                    missing[i] >= QLINQ_FEC_MAX_TOTAL_SYMBOLS) {
                  indices_valid = false;
                  break;
                }
              }
              if (indices_valid)
                missing_count =
                    transport_repair_normalize_indices(missing, missing_count);
            }

            bool whole_object =
                (nack.flags & QLINQ_WIRE_NACK_WHOLE_OBJECT) != 0;
            if (repair_mode == TRANSPORT_REPAIR_MODE_RATELESS && whole_object) {
              missing_count = cached->data_symbols;
              if (missing_count > TRANSPORT_REPAIR_MAX_SYMBOLS)
                missing_count = TRANSPORT_REPAIR_MAX_SYMBOLS;
            }
            int64_t now = transport_get_time_ms();
            if (!transport_repair_limiter_take(
                    &t->aggregate_repair_limiter,
                    t->limits.max_aggregate_repair_requests_per_second, now)) {
              t->stats.repair_requests_aggregate_throttled++;
              quicly_streambuf_ingress_shift(stream, frame.consumed);
              continue;
            }
            transport_repair_batch_t repair;
            bool systematic_fallback = false;
            bool built =
                indices_valid &&
                (repair_mode == TRANSPORT_REPAIR_MODE_RATELESS
                     ? transport_repair_build_rateless(&t->fec_cache, cached,
                                                       missing_count, &repair)
                     : transport_repair_build(&t->fec_cache, cached,
                                              whole_object, missing,
                                              missing_count, &repair));
            if (!built && indices_valid &&
                repair_mode == TRANSPORT_REPAIR_MODE_RATELESS &&
                cached->next_repair_symbol >= QLINQ_FEC_MAX_TOTAL_SYMBOLS) {
              t->stats.repair_rateless_exhausted++;
              built = transport_repair_build_systematic_fallback(
                  &t->fec_cache, cached, missing_count, &repair);
              systematic_fallback = built;
            }
            if (built) {
              size_t repairs_queued = 0;
              for (size_t i = 0; i < repair.count; i++) {
                uint8_t packet[QLINQ_WIRE_FEC_HEADER_SIZE +
                               QLINQ_FEC_MAX_SYMBOL_SIZE];
                size_t packet_len =
                    QLINQ_WIRE_FEC_HEADER_SIZE + repair.symbol_size;
                qlinq_wire_fec_header_t header = {
                    .alias = nack.alias,
                    .is_keyframe = cached->is_keyframe,
                    .priority = cached->priority,
                    .path_id = 0,
                    .group_id = cached->group_id,
                    .object_id = cached->object_id,
                    .symbol_index = repair.indices[i],
                    .total_symbols = repair.total_symbols,
                    .data_symbols = cached->data_symbols,
                    .symbol_size = repair.symbol_size,
                    .original_size = (uint32_t)cached->size,
                    .send_time_ns = transport_get_time_ns()};
                if (qlinq_wire_encode_fec_header(packet, sizeof(packet),
                                                 &header) != QLINQ_WIRE_OK)
                  break;
                memcpy(packet + QLINQ_WIRE_FEC_HEADER_SIZE,
                       repair.symbols + i * repair.symbol_size,
                       repair.symbol_size);
                ptls_iovec_t datagram = ptls_iovec_init(packet, packet_len);
                if (!transport_queue_datagram(conn, 0, datagram))
                  break;
                repairs_queued++;
              }
              if (repairs_queued != 0 &&
                  repair_mode == TRANSPORT_REPAIR_MODE_RATELESS) {
                bool committed =
                    systematic_fallback
                        ? transport_repair_commit_systematic_fallback(
                              cached, &repair, repairs_queued)
                        : transport_repair_commit_rateless(cached, &repair,
                                                           repairs_queued);
                if (!committed)
                  t->stats.protocol_errors++;
              }
              t->stats.repair_symbols_sent += repairs_queued;
              if (repair_mode == TRANSPORT_REPAIR_MODE_RATELESS)
                t->stats.repair_rateless_symbols_sent += repairs_queued;
              transport_repair_batch_destroy(&repair);
            }
          }
        }
      }
      quicly_streambuf_ingress_shift(stream, frame.consumed);
    } else if (type == QLINQ_WIRE_TRACK_CHECKPOINT) {
      qlinq_wire_track_checkpoint_t checkpoint;
      moq_track_id_t resolved_track;
      if (!conn->authenticated ||
          (conn->peer_capabilities & QLINQ_WIRE_CAP_RECOVERY_CHECKPOINTS) ==
              0 ||
          qlinq_wire_decode_track_checkpoint(input.base, input.len,
                                             &checkpoint) != QLINQ_WIRE_OK ||
          transport_subscriptions_find_by_alias(&conn->receive_subscriptions,
                                                checkpoint.alias,
                                                &resolved_track) != 0 ||
          resolved_track.type != MOQ_TRACK_DATA ||
          (resolved_track.flags & MOQ_TRACK_FLAG_FEC_RATELESS) == 0) {
        quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL,
                     "protocol error: invalid recovery checkpoint");
        break;
      }
      if ((checkpoint.flags & QLINQ_WIRE_CHECKPOINT_BASELINE) != 0) {
        transport_object_gap_state_t *gap =
            transport_object_gap(conn, checkpoint.alias);
        if (checkpoint.first_object_id != checkpoint.final_object_id ||
            (gap->checkpoint_initialized &&
             checkpoint.final_object_id < gap->last_checkpoint_object_id) ||
            !send_checkpoint_ack(conn, checkpoint.alias, checkpoint.group_id,
                                 checkpoint.final_object_id)) {
          quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL,
                       "protocol error: invalid recovery baseline");
          break;
        }
        gap->checkpoint_initialized = true;
        gap->last_checkpoint_object_id = checkpoint.final_object_id;
      } else if (!receive_recovery_checkpoint(
                     conn, checkpoint.alias, checkpoint.group_id,
                     checkpoint.first_object_id, checkpoint.final_object_id,
                     true)) {
        quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL,
                     "protocol error: invalid recovery checkpoint window");
        break;
      }
      t->stats.recovery_checkpoints_received++;
      quicly_streambuf_ingress_shift(stream, frame.consumed);
    } else if (type == QLINQ_WIRE_TRACK_CHECKPOINT_ACK) {
      qlinq_wire_track_checkpoint_ack_t ack;
      moq_track_id_t resolved_track;
      if (!conn->authenticated ||
          qlinq_wire_decode_track_checkpoint_ack(input.base, input.len, &ack) !=
              QLINQ_WIRE_OK ||
          transport_subscriptions_find_by_alias(
              &conn->send_subscriptions, ack.alias, &resolved_track) != 0 ||
          resolved_track.type != MOQ_TRACK_DATA ||
          (resolved_track.flags & MOQ_TRACK_FLAG_FEC_RATELESS) == 0 ||
          !transport_publish_checkpoint_acked(t, conn, &ack, &resolved_track)) {
        quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL,
                     "protocol error: invalid recovery checkpoint ACK");
        break;
      }
      t->stats.recovery_checkpoint_acks_received++;
      quicly_streambuf_ingress_shift(stream, frame.consumed);
    } else if (type == QLINQ_WIRE_TRACK_END) {
      qlinq_wire_track_end_t end;
      moq_track_id_t resolved_track;
      if (!conn->authenticated ||
          qlinq_wire_decode_track_end(input.base, input.len, &end) !=
              QLINQ_WIRE_OK ||
          transport_subscriptions_find_by_alias(
              &conn->receive_subscriptions, end.alias, &resolved_track) != 0 ||
          resolved_track.type != MOQ_TRACK_DATA ||
          (resolved_track.flags & MOQ_TRACK_FLAG_FEC_RATELESS) == 0) {
        quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL,
                     "protocol error: invalid track completion");
        break;
      }

      transport_object_gap_state_t *gap = transport_object_gap(conn, end.alias);
      bool acknowledge =
          (conn->peer_capabilities & QLINQ_WIRE_CAP_RECOVERY_CHECKPOINTS) != 0;
      uint64_t first_object_id = 0;
      if (acknowledge && gap->checkpoint_initialized) {
        if (end.final_object_id <= gap->last_checkpoint_object_id) {
          bool outstanding = false;
          for (size_t i = 0; i < QLINQ_RECOVERY_MAX_WINDOWS; i++)
            outstanding |= gap->recovery_windows[i].active;
          if (!outstanding) {
            if (!send_checkpoint_ack(conn, end.alias, end.group_id,
                                     end.final_object_id)) {
              quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL,
                           "protocol error: completion ACK failed");
              break;
            }
            retire_recovery_through(conn, end.alias, end.group_id,
                                    end.final_object_id);
          }
          t->stats.track_ends_received++;
          quicly_streambuf_ingress_shift(stream, frame.consumed);
          continue;
        }
        first_object_id = gap->last_checkpoint_object_id + 1U;
      } else {
        first_object_id =
            end.final_object_id >= 31 ? end.final_object_id - 31 : 0;
      }
      if (!receive_recovery_checkpoint(conn, end.alias, end.group_id,
                                       first_object_id, end.final_object_id,
                                       acknowledge)) {
        quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL,
                     "protocol error: invalid track completion window");
        break;
      }
      t->stats.track_ends_received++;
      quicly_streambuf_ingress_shift(stream, frame.consumed);
    } else {
      quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL,
                   "protocol error: unexpected frame");
      break;
    }
  }
}

static void on_stream_destroy(quicly_stream_t *stream, quicly_error_t err) {
  transport_conn_t *conn = *quicly_get_data(stream->conn);
  if (conn) {
    transport_subscriptions_clear_stream(&conn->receive_subscriptions, stream);
    transport_subscriptions_clear_stream(&conn->send_subscriptions, stream);
  }
  transport_stream_destroy(stream, err);
}

static void parse_track_stream_messages(transport_t *t, transport_conn_t *conn,
                                        quicly_stream_t *stream) {
  transport_stream_ctx_t *ctx = (transport_stream_ctx_t *)stream->data;
  while (1) {
    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);
    if (input.len == 0)
      break;

    qlinq_wire_frame_t frame;
    qlinq_wire_result_t result = qlinq_wire_decode_frame(
        input.base, input.len, TRANSPORT_WIRE_MAX_STREAM_PAYLOAD, &frame);
    if (result == QLINQ_WIRE_NEED_MORE)
      break;
    if (result != QLINQ_WIRE_OK) {
      close_wire_error(conn, result);
      break;
    }
    t->stats.stream_frames_received++;
    conn->stream_frames_received++;
    if (frame.type != QLINQ_WIRE_TRACK_OBJECT ||
        frame.payload_len < QLINQ_WIRE_TRACK_OBJECT_HEADER_SIZE) {
      quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL,
                   "protocol error: unexpected track frame");
      break;
    }

    if (!conn->authenticated) {
      quicly_close(conn->quic, TRANSPORT_APP_ERROR_AUTHENTICATION,
                   "unauthorized");
      break;
    }

    qlinq_wire_track_object_t wire_object;
    const uint8_t *object_payload = NULL;
    size_t payload_size = 0;
    if (qlinq_wire_decode_track_object(frame.payload, frame.payload_len,
                                       &wire_object, &object_payload,
                                       &payload_size) != QLINQ_WIRE_OK) {
      quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL,
                   "protocol error: invalid track object");
      break;
    }
    if (payload_size > conn->negotiated_limits.max_reliable_object_size) {
      t->stats.resource_limit_errors++;
      quicly_close(conn->quic, TRANSPORT_APP_ERROR_RESOURCE_LIMIT,
                   "protocol error: reliable object too large");
      break;
    }
    uint8_t alias = wire_object.alias;
    if (ctx->alias_bound && ctx->alias != alias) {
      quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL,
                   "protocol error: track alias changed");
      break;
    }
    if (!ctx->alias_bound) {
      ctx->alias = alias;
      ctx->alias_bound = true;
      if (transport_subscriptions_bind_stream(&conn->receive_subscriptions,
                                              alias, stream))
        quicly_debug_printf(conn->quic,
                            "Mapped incoming QUIC Stream %" PRIu64
                            " to MoQ track alias %d",
                            stream->stream_id, alias);
    }

    moq_track_id_t resolved_track = {0};
    if (transport_subscriptions_find_by_alias(&conn->receive_subscriptions,
                                              alias, &resolved_track) == 0) {
      if ((resolved_track.flags & MOQ_TRACK_FLAG_RELIABLE) == 0) {
        t->stats.protocol_errors++;
        quicly_close(conn->quic, TRANSPORT_APP_ERROR_PROTOCOL,
                     "protocol error: stream on datagram track");
        break;
      }
      transport_event_t ev = {.type = TRANSPORT_EVENT_OBJECT,
                              .conn = conn,
                              .track_id = resolved_track,
                              .object = {.track_id = resolved_track,
                                         .group_id = wire_object.group_id,
                                         .object_id = wire_object.object_id,
                                         .data = object_payload,
                                         .size = payload_size,
                                         .is_keyframe = wire_object.is_keyframe,
                                         .priority = wire_object.priority}};
      transport_emit_event(t, &ev);
    }

    quicly_streambuf_ingress_shift(stream, frame.consumed);
  }
}

/* control stream receive callbacks */
static void on_receive(quicly_stream_t *stream, size_t off, const void *src,
                       size_t len) {
  if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
    return;

  transport_conn_t *conn = *quicly_get_data(stream->conn);
  if (conn) {
    transport_stream_ctx_t *ctx = (transport_stream_ctx_t *)stream->data;
    if (ctx->is_control) {
      parse_control_messages(conn->transport, conn, stream);
    } else {
      parse_track_stream_messages(conn->transport, conn, stream);
    }
  }
}

static void on_stop_sending(quicly_stream_t *stream, quicly_error_t err) {
  transport_stream_ctx_t *ctx = (transport_stream_ctx_t *)stream->data;
  if (ctx && ctx->is_control) {
    quicly_close(stream->conn, 0, "");
  } else {
    quicly_reset_stream(stream, err);
  }
}

static void on_receive_reset(quicly_stream_t *stream, quicly_error_t err) {
  transport_stream_ctx_t *ctx = (transport_stream_ctx_t *)stream->data;
  if (ctx && ctx->is_control) {
    quicly_close(stream->conn, 0, "");
  } else {
    quicly_reset_stream(stream, err);
  }
}

static quicly_error_t on_stream_open(quicly_stream_open_t *self,
                                     quicly_stream_t *stream) {
  (void)self;
  static const quicly_stream_callbacks_t stream_callbacks = {
      on_stream_destroy,
      transport_stream_egress_shift,
      quicly_streambuf_egress_emit,
      on_stop_sending,
      on_receive,
      on_receive_reset};
  int ret;

  if ((ret = quicly_streambuf_create(stream, sizeof(transport_stream_ctx_t))) !=
      0)
    return ret;
  stream->callbacks = &stream_callbacks;

  transport_stream_ctx_t *ctx = (transport_stream_ctx_t *)stream->data;
  ctx->owner = NULL;
  ctx->retained_frame_bytes = 0;
  ctx->is_control = (stream->stream_id == 0);
  ctx->alias_bound = false;

  /* client saves the stream pointer */
  transport_conn_t *conn = *quicly_get_data(stream->conn);
  if (conn && ctx->is_control) {
    conn->stream = stream;
  }

  return 0;
}

/* handle incoming datagram frames */
bool transport_protocol_send_nack(transport_conn_t *conn, uint8_t alias,
                                  uint64_t group_id, uint64_t object_id,
                                  const uint16_t *missing, uint16_t count,
                                  bool whole_object) {
  if (!conn || !conn->stream ||
      !quicly_sendstate_is_open(&conn->stream->sendstate))
    return false;

  if (count > QLINQ_WIRE_MAX_NACK_SYMBOLS)
    return false;
  moq_track_id_t track_id;
  if (transport_subscriptions_find_by_alias(&conn->receive_subscriptions, alias,
                                            &track_id) != 0)
    return false;
  bool rateless =
      transport_get_effective_repair_mode(conn->transport, conn, &track_id) ==
      TRANSPORT_REPAIR_MODE_RATELESS;
  if (rateless ? (!whole_object && (count == 0 || missing != NULL))
               : (!whole_object && (count == 0 || missing == NULL)))
    return false;
  size_t payload_len = 20U + (rateless ? 0U : (size_t)count * 2U);
  uint8_t static_buf[1024];
  uint8_t *buf = static_buf;
  if (payload_len > sizeof(static_buf)) {
    buf = malloc(payload_len);
    if (!buf)
      return false;
  }

  size_t written = 0;
  bool sent = false;
  uint8_t flags = whole_object ? QLINQ_WIRE_NACK_WHOLE_OBJECT : 0;
  if (rateless)
    flags |= QLINQ_WIRE_NACK_RATELESS;
  if (qlinq_wire_encode_nack(buf, payload_len, alias, flags, group_id,
                             object_id, missing, count,
                             &written) == QLINQ_WIRE_OK) {
    if (transport_stream_has_retained_frame(conn->stream, QLINQ_WIRE_NACK, buf,
                                            written)) {
      /* QUIC owns retransmission until this exact request is released. A
       * later application retry can recover a lost repair response. */
      conn->transport->stats.repair_requests_coalesced++;
      sent = true;
    } else if (!transport_stream_can_accept(
                   conn->stream, QLINQ_WIRE_FRAME_HEADER_SIZE + written,
                   true)) {
      /* Recovery timers retain the missing objects and retry after pressure
       * clears. Preserve essential control capacity without spending tokens. */
      conn->transport->stats.repair_requests_deferred++;
    } else if (transport_repair_limiter_wait_ms(
                   &conn->nack_request_limiter,
                   conn->transport->limits.max_repair_requests_per_second,
                   transport_get_time_ms()) != 0 ||
               transport_repair_limiter_wait_ms(
                   &conn->transport->aggregate_nack_limiter,
                   conn->transport->limits
                       .max_aggregate_nack_requests_per_second,
                   transport_get_time_ms()) != 0) {
      conn->transport->stats.repair_requests_deferred++;
    } else if (transport_stream_write_frame(conn->stream, QLINQ_WIRE_NACK, buf,
                                            written)) {
      int64_t admitted_at_ms = transport_get_time_ms();
      (void)transport_repair_limiter_take(
          &conn->nack_request_limiter,
          conn->transport->limits.max_repair_requests_per_second,
          admitted_at_ms);
      (void)transport_repair_limiter_take(
          &conn->transport->aggregate_nack_limiter,
          conn->transport->limits.max_aggregate_nack_requests_per_second,
          admitted_at_ms);
      conn->transport->stats.repair_requests_sent++;
      if (rateless)
        conn->transport->stats.repair_rateless_requests_sent++;
      else
        conn->transport->stats.repair_indexed_requests_sent++;
      if (whole_object)
        conn->transport->stats.repair_whole_object_requests_sent++;
      sent = true;
    }
  }

  if (buf != static_buf) {
    free(buf);
  }
  return sent;
}

static void on_receive_datagram_frame(quicly_receive_datagram_frame_t *self,
                                      quicly_conn_t *conn,
                                      ptls_iovec_t payload) {
  (void)self;
  transport_conn_t *tconn = *quicly_get_data(conn);
  if (!tconn)
    return;

  transport_t *t = tconn->transport;
  t->stats.datagrams_received++;
  tconn->datagrams_received++;
  if (!tconn->authenticated)
    return;

  uint8_t datagram_type;
  qlinq_wire_result_t wire_result = qlinq_wire_decode_datagram_type(
      payload.base, payload.len, &datagram_type);
  if (wire_result != QLINQ_WIRE_OK) {
    t->stats.malformed_datagrams++;
    tconn->malformed_datagrams++;
    return;
  }

  if (datagram_type == QLINQ_WIRE_DATAGRAM_TELEMETRY) {
    qlinq_wire_telemetry_t telemetry;
    if (qlinq_wire_decode_telemetry(payload.base, payload.len, &telemetry) !=
        QLINQ_WIRE_OK) {
      t->stats.malformed_datagrams++;
      tconn->malformed_datagrams++;
      return;
    }
    /* The wire carries a QUIC path index, while scheduling state follows
     * physical sockets (which can be compacted after interface removal). */
    size_t pid = SIZE_MAX;
    quicly_path_stats_t path;
    if (quicly_get_path_stats(conn, telemetry.path_id, &path) == 0 &&
        quicly_is_path_available(conn, telemetry.path_id)) {
      for (size_t i = 0; i < t->num_fds; i++) {
        if (transport_path_matches_local(&path, &t->local_addrs[i])) {
          pid = i;
          break;
        }
      }
    }
    if (pid == SIZE_MAX)
      return; /* A delayed reply may refer to a retired path. */
    uint64_t s_ns = telemetry.send_time_ns, r_ns = telemetry.recv_time_ns;
    if (s_ns > INT64_MAX || r_ns > INT64_MAX) {
      t->stats.malformed_datagrams++;
      tconn->malformed_datagrams++;
      return;
    }
    if (tconn->owd_initialized[pid] &&
        tconn->telemetry_path[pid] == telemetry.path_id &&
        s_ns <= tconn->last_telemetry_s_ns[pid])
      return; /* Do not let reordered replies move a newer baseline. */

    /* Both operands are nonnegative signed values, so their difference fits.
     * Subtract the baseline as unsigned to represent the full possible span. */
    int64_t current = (int64_t)r_ns - (int64_t)s_ns;
    uint64_t relative = 0;
    if (!tconn->owd_initialized[pid] ||
        tconn->telemetry_path[pid] != telemetry.path_id ||
        current < tconn->min_owd_ns[pid]) {
      tconn->min_owd_ns[pid] = current;
    } else {
      relative = (uint64_t)current - (uint64_t)tconn->min_owd_ns[pid];
      /* Beyond ten seconds this is not a useful queue-delay sample. Treat it
       * as a clock discontinuity and establish a fresh baseline. */
      if (relative > UINT64_C(10000000000)) {
        tconn->min_owd_ns[pid] = current;
        relative = 0;
      }
    }
    tconn->owd_initialized[pid] = true;
    tconn->telemetry_path[pid] = telemetry.path_id;
    tconn->latest_owd_fp[pid] = FP_FROM_INT(relative / 1000U) / 1000000;
    tconn->last_telemetry_s_ns[pid] = s_ns;
    tconn->last_telemetry_r_ns[pid] = r_ns;
    return;
  }

  qlinq_wire_fec_header_t hdr;
  if (qlinq_wire_decode_fec_header(payload.base, payload.len, &hdr) !=
      QLINQ_WIRE_OK) {
    t->stats.malformed_datagrams++;
    tconn->malformed_datagrams++;
    return;
  }

  uint8_t track_id = hdr.alias;
  moq_track_id_t resolved_track;
  if (transport_subscriptions_find_by_alias(&tconn->receive_subscriptions,
                                            track_id, &resolved_track) != 0) {
    return;
  }

  if ((resolved_track.flags & MOQ_TRACK_FLAG_RELIABLE) != 0) {
    t->stats.protocol_errors++;
    quicly_close(conn, TRANSPORT_APP_ERROR_PROTOCOL,
                 "protocol error: datagram on reliable track");
    return;
  }

  /* automatically send a telemetry reply to measure OWD */
  uint8_t reply[QLINQ_WIRE_TELEMETRY_SIZE];
  qlinq_wire_telemetry_t telemetry = {.path_id = hdr.path_id,
                                      .send_time_ns = hdr.send_time_ns,
                                      .recv_time_ns = transport_get_time_ns()};
  if (qlinq_wire_encode_telemetry(reply, sizeof(reply), &telemetry) ==
      QLINQ_WIRE_OK) {
    ptls_iovec_t reply_vec = ptls_iovec_init(reply, sizeof(reply));
    (void)transport_queue_datagram(tconn, hdr.path_id, reply_vec);
  }

  uint8_t is_keyframe = hdr.is_keyframe;
  uint64_t group_id = hdr.group_id;
  uint64_t object_id = hdr.object_id;
  uint16_t symbol_index = hdr.symbol_index;
  uint16_t total_symbols = hdr.total_symbols;
  uint16_t data_symbols = hdr.data_symbols;
  uint16_t symbol_size = hdr.symbol_size;
  uint32_t original_size = hdr.original_size;

  if (total_symbols == 0 || total_symbols > QLINQ_FEC_MAX_TOTAL_SYMBOLS ||
      symbol_size == 0 || symbol_size > QLINQ_FEC_MAX_SYMBOL_SIZE ||
      data_symbols == 0 || data_symbols > total_symbols ||
      symbol_index >= total_symbols)
    goto malformed_datagram;

  if (original_size > tconn->negotiated_limits.max_fec_object_size ||
      original_size > (uint32_t)data_symbols * symbol_size ||
      original_size == 0)
    goto malformed_datagram;

  if (payload.len != QLINQ_WIRE_FEC_HEADER_SIZE + symbol_size)
    goto malformed_datagram;

  bool rateless = (resolved_track.flags & MOQ_TRACK_FLAG_FEC_RATELESS) != 0;
  bool rateless_data = resolved_track.type == MOQ_TRACK_DATA && rateless;
  transport_subscription_state_t *subscription_state =
      transport_subscriptions_get_state(&tconn->receive_subscriptions,
                                        track_id);
  if (!subscription_state)
    return;
  uint64_t generation = subscription_state->generation;
  transport_object_gap_state_t *object_state = &subscription_state->object_gap;
  for (size_t i = 0; i < QLINQ_COMPLETED_OBJECTS; i++) {
    if (tconn->completed_objects[i].active &&
        tconn->completed_objects[i].alias == track_id &&
        tconn->completed_objects[i].generation == generation &&
        tconn->completed_objects[i].group_id == group_id &&
        tconn->completed_objects[i].object_id == object_id) {
      t->stats.fec_duplicate_objects_suppressed++;
      return;
    }
  }
  if (rateless_data && object_was_delivered(object_state, object_id)) {
    t->stats.fec_duplicate_objects_suppressed++;
    return;
  }

  if (rateless_data) {
    transport_object_gap_state_t *gap = object_state;
    if (!gap->seen_initialized) {
      gap->seen_initialized = true;
      gap->last_seen = object_id;
    } else if (object_id > gap->last_seen) {
      if (object_id - gap->last_seen > 1) {
        uint64_t first_missing = gap->last_seen + 1;
        uint64_t missing_count = object_id - first_missing;
        (void)queue_missing_objects(gap, group_id, first_missing,
                                    missing_count);
      }
      gap->last_seen = object_id;
    } else if (gap->pending_mask != 0 && object_id >= gap->pending_base &&
               object_id - gap->pending_base < 32) {
      gap->pending_mask &= ~(1U << (object_id - gap->pending_base));
    }
  }

  /* lookup active frame assembler cache */
  frame_assembler_t *asm_slot = NULL;
  for (size_t i = 0; i < t->limits.max_assemblers_per_connection; i++) {
    frame_assembler_t *a = &tconn->assemblers[i];
    if (a->total_symbols > 0 && a->track_id == track_id &&
        a->group_id == group_id && a->object_id == object_id) {
      if (a->symbol_size != symbol_size || a->data_symbols != data_symbols ||
          a->original_size != original_size) {
        goto malformed_datagram;
      }
      asm_slot = a;
      break;
    }
  }

  if (!asm_slot) {
    /* Completed small records leave reusable slots behind. Do not evict a
     * still-assembling image merely because the round-robin cursor wrapped
     * after several chat/PLI records. Preserve bounded eviction only when
     * every slot is actually occupied. */
    for (size_t offset = 0; offset < t->limits.max_assemblers_per_connection;
         offset++) {
      size_t index = (tconn->assembler_index + offset) %
                     t->limits.max_assemblers_per_connection;
      if (tconn->assemblers[index].total_symbols == 0) {
        tconn->assembler_index = index;
        break;
      }
    }
    asm_slot = &tconn->assemblers[tconn->assembler_index];
    tconn->assembler_index =
        (tconn->assembler_index + 1) % t->limits.max_assemblers_per_connection;

    if (asm_slot->total_symbols > 0 && !asm_slot->decoded) {
      moq_track_id_t resolved_track;
      if (transport_subscriptions_find_by_alias(&tconn->receive_subscriptions,
                                                asm_slot->track_id,
                                                &resolved_track) == 0) {
        transport_event_t ev = {.type = TRANSPORT_EVENT_OBJECT_LOST,
                                .conn = tconn,
                                .track_id = resolved_track,
                                .object = {.track_id = resolved_track,
                                           .group_id = asm_slot->group_id,
                                           .object_id = asm_slot->object_id}};
        t->stats.fec_objects_lost++;
        transport_emit_event(tconn->transport, &ev);
        /* A loss callback may unsubscribe and reuse this alias. Never retain
         * state across that boundary without checking its lifetime. */
        subscription_state = transport_subscriptions_get_state(
            &tconn->receive_subscriptions, track_id);
        if (!subscription_state ||
            subscription_state->generation != generation ||
            quicly_get_state(conn) >= QUICLY_STATE_CLOSING)
          return;
        object_state = &subscription_state->object_gap;
      }
    }

    if (!asm_slot->buffers || asm_slot->capacity_symbols < total_symbols ||
        asm_slot->capacity_symbol_size < symbol_size) {
      transport_release_assembler(t, asm_slot);
      if (!transport_grow_assembler(t, asm_slot, total_symbols, symbol_size)) {
        transport_release_assembler(t, asm_slot);
        return;
      }
    }

    memset(asm_slot->received_mask, 0,
           asm_slot->capacity_symbols * sizeof(bool));
    asm_slot->track_id = track_id;
    asm_slot->group_id = group_id;
    asm_slot->object_id = object_id;
    asm_slot->total_symbols = total_symbols;
    asm_slot->data_symbols = data_symbols;
    asm_slot->symbol_size = symbol_size;
    asm_slot->original_size = original_size;
    asm_slot->priority = hdr.priority;
    asm_slot->decoded = false;
    asm_slot->received_count = 0;
    asm_slot->nack_sent = false;
    asm_slot->first_symbol_time_ms = transport_get_time_ms();
    asm_slot->last_activity_time_ms = asm_slot->first_symbol_time_ms;
  }

  if (asm_slot->decoded)
    return;

  if (total_symbols > asm_slot->total_symbols) {
    if (!transport_grow_assembler(t, asm_slot, total_symbols, symbol_size)) {
      return;
    }
    asm_slot->total_symbols = total_symbols;
  }

  total_symbols = asm_slot->total_symbols;
  data_symbols = asm_slot->data_symbols;
  symbol_size = asm_slot->symbol_size;
  original_size = asm_slot->original_size;

  if (symbol_index >= asm_slot->total_symbols)
    return;

  if (!asm_slot->received_mask[symbol_index]) {
    memcpy(asm_slot->buffers[symbol_index],
           payload.base + QLINQ_WIRE_FEC_HEADER_SIZE, symbol_size);
    asm_slot->received_mask[symbol_index] = true;
    asm_slot->received_count++;
    asm_slot->last_activity_time_ms = transport_get_time_ms();
  }

  if (asm_slot->received_count >= data_symbols) {
    bool got_all_data = true;
    for (size_t i = 0; i < data_symbols; i++) {
      if (!asm_slot->received_mask[i]) {
        got_all_data = false;
        break;
      }
    }

    bool success = false;
    if (got_all_data) {
      success = true;
    } else {
      size_t parity_symbols = total_symbols - data_symbols;
      if (parity_symbols > 0) {
        /* Match the sender's codec for every content type. DATA alone uses
         * the additional gap tracking and recovery-checkpoint machinery. */
        fec_type_t fec_type =
            rateless || total_symbols > 255 ? FEC_RAPTORQ : FEC_REED_SOLOMON;
        fec_t *fec = transport_fec_cache_get(
            &t->fec_cache, fec_type, data_symbols, parity_symbols, symbol_size);
        if (fec) {
          for (size_t i = 0; i < total_symbols; i++) {
            asm_slot->missing_mask[i] = !asm_slot->received_mask[i];
          }
          success = fec_decode(fec, asm_slot->buffers, asm_slot->missing_mask);
        }
      }
    }

    if (success) {
      uint8_t *full_data = malloc(original_size);
      if (!full_data)
        return; /* out of memory */
      size_t bytes_left = original_size;
      for (size_t i = 0; i < data_symbols; i++) {
        size_t chunk = (bytes_left < symbol_size) ? bytes_left : symbol_size;
        if (chunk > 0) {
          memcpy(full_data + (i * symbol_size), asm_slot->buffers[i], chunk);
          bytes_left -= chunk;
        }
      }

      /* Preserve the negotiated identity for every datagram delivery mode. */
      transport_event_t ev = {.type = TRANSPORT_EVENT_OBJECT,
                              .conn = tconn,
                              .track_id = resolved_track,
                              .object = {.track_id = resolved_track,
                                         .group_id = group_id,
                                         .object_id = object_id,
                                         .data = full_data,
                                         .size = original_size,
                                         .is_keyframe = (is_keyframe != 0),
                                         .priority = asm_slot->priority}};
      size_t completed = tconn->completed_cursor;
      tconn->completed_cursor = (completed + 1U) % QLINQ_COMPLETED_OBJECTS;
      tconn->completed_objects[completed].active = true;
      tconn->completed_objects[completed].alias = track_id;
      tconn->completed_objects[completed].generation = generation;
      tconn->completed_objects[completed].group_id = group_id;
      tconn->completed_objects[completed].object_id = object_id;
      if (rateless_data) {
        mark_object_delivered(object_state, object_id);
        recovery_mark_delivered(tconn, track_id, group_id, object_id);
      }
      t->stats.fec_objects_recovered++;
      transport_emit_event(t, &ev);
      free(full_data);
      transport_release_assembler(t, asm_slot);
    }
  }
  return;

malformed_datagram:
  t->stats.malformed_datagrams++;
  tconn->malformed_datagrams++;
}

void transport_protocol_setup(transport_t *t) {
  if (!t)
    return;
  t->stream_open.cb = on_stream_open;
  t->receive_datagram.cb = on_receive_datagram_frame;
}
