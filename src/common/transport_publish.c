#include "transport_publish.h"

#include "fec.h"
#include "portable_sockets.h"
#include "transport_fec_state.h"
#include "transport_scheduler.h"
#include "transport_stream.h"
#include "transport_subscriptions.h"
#include "transport_tracks.h"
#include "transport_wire.h"

#include "quicly/sendstate.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

static transport_publish_result_t
transport_publish_impl(transport_t *t, const moq_object_t *obj);

static bool transport_publish_recipient_eligible(const transport_t *t,
                                                 const transport_conn_t *conn,
                                                 const moq_track_id_t *track) {
  return t && conn && track && conn->quic && conn->protocol_ready &&
         conn->authenticated &&
         quicly_get_state(conn->quic) < QUICLY_STATE_CLOSING &&
         (!t->is_server ||
          transport_subscriptions_contains(&conn->subscriptions, track));
}

static size_t publication_fec_limit(const transport_t *t,
                                    const moq_track_id_t *track) {
  size_t limit = t->limits.max_fec_object_size;
  size_t count = t->is_server ? t->conn_count : (t->client_conn ? 1U : 0U);
  for (size_t i = 0; i < count; i++) {
    const transport_conn_t *conn = t->is_server ? t->conns[i] : t->client_conn;
    if (transport_publish_recipient_eligible(t, conn, track) &&
        conn->negotiated_limits.max_fec_object_size < limit)
      limit = conn->negotiated_limits.max_fec_object_size;
  }
  return limit;
}

static transport_publish_result_t publish_datagram_to_conn(
    transport_t *t, transport_conn_t *conn, const moq_object_t *obj,
    const transport_track_profile_t *profile, size_t symbol_size,
    size_t data_symbols, uint16_t *sent_total_symbols) {
  size_t active_physical[TRANSPORT_MAX_PATHS];
  path_state_t active_states[TRANSPORT_MAX_PATHS];
  size_t active_paths = 0;
  for (size_t physical = 0; physical < t->num_fds; physical++) {
    size_t mapped = transport_path_find_by_link(conn->quic, t->local_addrs,
                                                t->num_fds, physical);
    if (mapped >= TRANSPORT_MAX_QUIC_PATHS ||
        !quicly_is_path_available(conn->quic, mapped))
      continue;
    active_physical[active_paths] = physical;
    active_states[active_paths] = conn->path_states[physical];
    active_paths++;
  }
  if (active_paths == 0)
    return TRANSPORT_PUBLISH_BACKPRESSURE;

  transport_schedule_t schedule;
  bool use_fec = profile->fec_enabled || profile->fec_rateless;
  if (!transport_schedule_build(&conn->scheduler_context, conn->quic,
                                active_states, active_paths, data_symbols,
                                symbol_size, use_fec, obj->priority,
                                &conn->round_robin_path, &schedule))
    return TRANSPORT_PUBLISH_ERROR;

  size_t parity_symbols = schedule.parity_symbols;
  size_t total_symbols = data_symbols + parity_symbols;
  if (total_symbols > QLINQ_FEC_MAX_TOTAL_SYMBOLS || total_symbols > UINT16_MAX)
    return TRANSPORT_PUBLISH_INVALID;
  if (sent_total_symbols)
    *sent_total_symbols = (uint16_t)total_symbols;

  uint8_t **data_blocks =
      transport_arena_alloc(&t->arena, data_symbols * sizeof(*data_blocks));
  uint8_t **parity_blocks =
      transport_arena_alloc(&t->arena, parity_symbols * sizeof(*parity_blocks));
  if (!data_blocks || (parity_symbols > 0 && !parity_blocks)) {
    transport_arena_reset(&t->arena);
    return TRANSPORT_PUBLISH_ERROR;
  }

  for (size_t i = 0; i < data_symbols; i++) {
    size_t offset = i * symbol_size;
    size_t chunk = offset < obj->size ? obj->size - offset : 0;
    if (chunk >= symbol_size) {
      data_blocks[i] = (uint8_t *)obj->data + offset;
    } else {
      data_blocks[i] = transport_arena_alloc(&t->arena, symbol_size);
      if (!data_blocks[i]) {
        transport_arena_reset(&t->arena);
        return TRANSPORT_PUBLISH_ERROR;
      }
      memset(data_blocks[i], 0, symbol_size);
      if (chunk > 0)
        memcpy(data_blocks[i], obj->data + offset, chunk);
    }
  }

  for (size_t i = 0; i < parity_symbols; i++) {
    parity_blocks[i] = transport_arena_alloc(&t->arena, symbol_size);
    if (!parity_blocks[i]) {
      transport_arena_reset(&t->arena);
      return TRANSPORT_PUBLISH_ERROR;
    }
  }

  if (parity_symbols > 0) {
    fec_type_t fec_type = profile->fec_rateless || total_symbols > 255
                              ? FEC_RAPTORQ
                              : FEC_REED_SOLOMON;
    fec_t *fec = transport_fec_cache_get(&t->fec_cache, fec_type, data_symbols,
                                         parity_symbols, symbol_size);
    if (!fec ||
        !fec_encode(fec, (const uint8_t *const *)data_blocks, parity_blocks)) {
      transport_arena_reset(&t->arena);
      return TRANSPORT_PUBLISH_ERROR;
    }
  }

  uint16_t needed[TRANSPORT_MAX_QUIC_PATHS] = {0};
  for (size_t s = 0; s < total_symbols; s++) {
    size_t scheduled =
        transport_path_select_physical(schedule.paths, active_paths, s);
    size_t physical = active_physical[scheduled];
    size_t mapped = transport_path_find_by_link(conn->quic, t->local_addrs,
                                                t->num_fds, physical);
    if (mapped >= TRANSPORT_MAX_QUIC_PATHS ||
        ++needed[mapped] > QLINQ_PATH_DATAGRAM_QUEUE_CAPACITY ||
        conn->queued_datagrams[mapped] >
            QLINQ_PATH_DATAGRAM_QUEUE_CAPACITY - needed[mapped]) {
      transport_arena_reset(&t->arena);
      return TRANSPORT_PUBLISH_BACKPRESSURE;
    }
  }

  uint8_t alias;
  if (transport_subscriptions_find_alias(&conn->subscriptions, &obj->track_id,
                                         &alias) != 0) {
    transport_arena_reset(&t->arena);
    return TRANSPORT_PUBLISH_NO_RECIPIENTS;
  }

  size_t queued = 0;
  for (size_t s = 0; s < total_symbols; s++) {
    size_t pkt_len = QLINQ_WIRE_FEC_HEADER_SIZE + symbol_size;
    uint8_t *pkt_buf = transport_arena_alloc(&t->arena, pkt_len);
    if (!pkt_buf) {
      transport_arena_reset(&t->arena);
      return queued > 0 ? TRANSPORT_PUBLISH_PARTIAL : TRANSPORT_PUBLISH_ERROR;
    }
    size_t scheduled =
        transport_path_select_physical(schedule.paths, active_paths, s);
    size_t physical = active_physical[scheduled];
    size_t mapped = transport_path_find_by_link(conn->quic, t->local_addrs,
                                                t->num_fds, physical);
    if (mapped > UINT8_MAX) {
      transport_arena_reset(&t->arena);
      return queued > 0 ? TRANSPORT_PUBLISH_PARTIAL : TRANSPORT_PUBLISH_ERROR;
    }
    qlinq_wire_fec_header_t header = {.alias = alias,
                                      .is_keyframe = obj->is_keyframe,
                                      .priority = obj->priority,
                                      .path_id = (uint8_t)mapped,
                                      .group_id = obj->group_id,
                                      .object_id = obj->object_id,
                                      .symbol_index = (uint16_t)s,
                                      .total_symbols = (uint16_t)total_symbols,
                                      .data_symbols = (uint16_t)data_symbols,
                                      .symbol_size = (uint16_t)symbol_size,
                                      .original_size = (uint32_t)obj->size,
                                      .send_time_ns = transport_get_time_ns()};
    if (qlinq_wire_encode_fec_header(pkt_buf, pkt_len, &header) !=
        QLINQ_WIRE_OK) {
      transport_arena_reset(&t->arena);
      return queued > 0 ? TRANSPORT_PUBLISH_PARTIAL : TRANSPORT_PUBLISH_ERROR;
    }
    const uint8_t *symbol =
        s < data_symbols ? data_blocks[s] : parity_blocks[s - data_symbols];
    memcpy(pkt_buf + QLINQ_WIRE_FEC_HEADER_SIZE, symbol, symbol_size);
    ptls_iovec_t datagram = ptls_iovec_init(pkt_buf, pkt_len);
    if (!transport_queue_datagram(conn, mapped, datagram)) {
      transport_arena_reset(&t->arena);
      return queued > 0 ? TRANSPORT_PUBLISH_PARTIAL
                        : TRANSPORT_PUBLISH_BACKPRESSURE;
    }
    queued++;
  }

  transport_arena_reset(&t->arena);
  return TRANSPORT_PUBLISH_DELIVERED;
}

static transport_fec_track_state_t *
find_fec_track_state(transport_t *t, const moq_track_id_t *track_id,
                     bool create) {
  transport_fec_track_state_t *available = NULL;
  for (size_t i = 0; i < TRANSPORT_HARD_MAX_SUBSCRIPTIONS; i++) {
    transport_fec_track_state_t *state = &t->fec_tracks[i];
    if (state->active && transport_track_id_equal(&state->track_id, track_id))
      return state;
    if (!state->active && !available)
      available = state;
  }
  if (!create || !available)
    return NULL;
  available->track_id = *track_id;
  available->active = true;
  return available;
}

static bool
checkpoint_ack_pending(const transport_checkpoint_ack_state_t *state) {
  return state && state->sent_initialized &&
         (!state->acked_initialized ||
          state->acked_group_id != state->sent_group_id ||
          state->acked_object_id < state->sent_object_id);
}

static void checkpoint_mark_sent(transport_checkpoint_ack_state_t *state,
                                 uint64_t group_id, uint64_t object_id) {
  bool already_pending = checkpoint_ack_pending(state);
  state->sent_initialized = true;
  state->sent_group_id = group_id;
  state->sent_object_id = object_id;
  if (!already_pending || state->oldest_unacked_sent_at_ms <= 0)
    state->oldest_unacked_sent_at_ms = transport_get_time_ms();
}

static void release_acked_checkpoints(transport_t *t,
                                      const moq_track_id_t *track_id) {
  bool found_capable_member = false;
  bool found_legacy_member = false;
  bool minimum_initialized = false;
  uint64_t minimum_group_id = 0;
  uint64_t minimum_object_id = 0;
  size_t active_count = t->is_server ? t->conn_count : (t->client_conn ? 1 : 0);
  for (size_t i = 0; i < active_count; i++) {
    transport_conn_t *conn = t->is_server ? t->conns[i] : t->client_conn;
    uint8_t alias = 0;
    if (!conn || transport_subscriptions_find_alias(&conn->subscriptions,
                                                    track_id, &alias) != 0)
      continue;
    if ((conn->peer_capabilities & QLINQ_WIRE_CAP_RECOVERY_CHECKPOINTS) == 0) {
      found_legacy_member = true;
      continue;
    }
    transport_checkpoint_ack_state_t *state = &conn->checkpoint_acks[alias];
    if (!state->participating)
      continue;
    found_capable_member = true;
    if (!state->acked_initialized)
      return;
    if (!minimum_initialized || state->acked_object_id < minimum_object_id) {
      minimum_initialized = true;
      minimum_group_id = state->acked_group_id;
      minimum_object_id = state->acked_object_id;
    } else if (state->acked_group_id != minimum_group_id) {
      return;
    }
  }
  if (found_legacy_member)
    return;
  size_t released = 0;
  if (found_capable_member && minimum_initialized)
    released = transport_sent_cache_release_through(
        &t->sent_cache, track_id, minimum_group_id, minimum_object_id);
  else if (!found_capable_member)
    released = transport_sent_cache_release_track(&t->sent_cache, track_id);
  t->stats.recovery_cache_releases += released;
}

void transport_publish_checkpoint_member_added(transport_t *t,
                                               transport_conn_t *conn,
                                               const moq_track_id_t *track_id,
                                               uint8_t alias) {
  if (!t || !conn || !track_id ||
      (conn->peer_capabilities & QLINQ_WIRE_CAP_RECOVERY_CHECKPOINTS) == 0 ||
      track_id->type != MOQ_TRACK_DATA ||
      (track_id->flags & MOQ_TRACK_FLAG_FEC_RATELESS) == 0)
    return;
  transport_checkpoint_ack_state_t *ack = &conn->checkpoint_acks[alias];
  memset(ack, 0, sizeof(*ack));
  ack->participating = true;

  transport_fec_track_state_t *track = find_fec_track_state(t, track_id, false);
  if (track && track->checkpoint_initialized && conn->stream &&
      quicly_sendstate_is_open(&conn->stream->sendstate) &&
      transport_stream_write_track_checkpoint_frame(
          conn->stream, alias, track->checkpoint_group_id,
          track->last_checkpoint_object_id, track->last_checkpoint_object_id,
          true)) {
    ack->sent_initialized = true;
    ack->sent_group_id = track->checkpoint_group_id;
    ack->sent_object_id = track->last_checkpoint_object_id;
    ack->acked_initialized = true;
    ack->acked_group_id = track->checkpoint_group_id;
    ack->acked_object_id = track->last_checkpoint_object_id;
    t->stats.recovery_checkpoints_sent++;
  }
}

void transport_publish_checkpoint_member_removed(transport_t *t,
                                                 transport_conn_t *conn,
                                                 const moq_track_id_t *track_id,
                                                 uint8_t alias) {
  if (!t || !conn || !track_id)
    return;
  memset(&conn->checkpoint_acks[alias], 0,
         sizeof(conn->checkpoint_acks[alias]));
  release_acked_checkpoints(t, track_id);
}

void transport_publish_checkpoint_connection_removed(transport_t *t,
                                                     transport_conn_t *conn) {
  if (!t || !conn)
    return;
  for (size_t i = 0; i < conn->subscriptions.capacity; i++) {
    track_subscription_t *subscription = &conn->subscriptions.entries[i];
    if (!subscription->active)
      continue;
    uint8_t alias = subscription->alias;
    if (!conn->checkpoint_acks[alias].participating)
      continue;
    moq_track_id_t track_id = subscription->track_id;
    memset(&conn->checkpoint_acks[alias], 0,
           sizeof(conn->checkpoint_acks[alias]));
    release_acked_checkpoints(t, &track_id);
  }
}

bool transport_publish_checkpoint_acked(
    transport_t *t, transport_conn_t *conn,
    const qlinq_wire_track_checkpoint_ack_t *ack,
    const moq_track_id_t *track_id) {
  if (!t || !conn || !ack || !track_id ||
      (conn->peer_capabilities & QLINQ_WIRE_CAP_RECOVERY_CHECKPOINTS) == 0)
    return false;
  transport_checkpoint_ack_state_t *state = &conn->checkpoint_acks[ack->alias];
  if (!state->participating || !state->sent_initialized ||
      ack->group_id != state->sent_group_id ||
      ack->final_object_id > state->sent_object_id)
    return false;
  bool advanced = !state->acked_initialized ||
                  ack->final_object_id > state->acked_object_id;
  if (advanced) {
    state->acked_initialized = true;
    state->acked_group_id = ack->group_id;
    state->acked_object_id = ack->final_object_id;
  }
  if (!checkpoint_ack_pending(state))
    state->oldest_unacked_sent_at_ms = 0;
  else if (advanced)
    state->oldest_unacked_sent_at_ms = transport_get_time_ms();
  release_acked_checkpoints(t, track_id);
  return true;
}

static bool checkpoint_cache_is_protected(transport_t *t,
                                          const moq_track_id_t *track_id) {
  bool found = false;
  size_t active_count = t->is_server ? t->conn_count : (t->client_conn ? 1 : 0);
  for (size_t i = 0; i < active_count; i++) {
    transport_conn_t *conn = t->is_server ? t->conns[i] : t->client_conn;
    uint8_t alias = 0;
    if (!conn || transport_subscriptions_find_alias(&conn->subscriptions,
                                                    track_id, &alias) != 0)
      continue;
    if ((conn->peer_capabilities & QLINQ_WIRE_CAP_RECOVERY_CHECKPOINTS) == 0)
      return false;
    if (conn->checkpoint_acks[alias].participating)
      found = true;
  }
  return found;
}

static bool emit_rolling_checkpoint(transport_t *t,
                                    transport_fec_track_state_t *track,
                                    uint64_t group_id, uint64_t first_object_id,
                                    uint64_t final_object_id) {
  bool succeeded = true;
  size_t active_count = t->is_server ? t->conn_count : (t->client_conn ? 1 : 0);
  for (size_t i = 0; i < active_count; i++) {
    transport_conn_t *conn = t->is_server ? t->conns[i] : t->client_conn;
    uint8_t alias = 0;
    if (!conn || !conn->quic || !conn->protocol_ready || !conn->authenticated ||
        !conn->stream || !quicly_sendstate_is_open(&conn->stream->sendstate) ||
        quicly_get_state(conn->quic) >= QUICLY_STATE_CLOSING ||
        (conn->peer_capabilities & QLINQ_WIRE_CAP_RECOVERY_CHECKPOINTS) == 0 ||
        transport_subscriptions_find_alias(&conn->subscriptions,
                                           &track->track_id, &alias) != 0)
      continue;
    if (!conn->checkpoint_acks[alias].participating)
      transport_publish_checkpoint_member_added(t, conn, &track->track_id,
                                                alias);
    if (!transport_stream_write_track_checkpoint_frame(
            conn->stream, alias, group_id, first_object_id, final_object_id,
            false)) {
      succeeded = false;
      continue;
    }
    checkpoint_mark_sent(&conn->checkpoint_acks[alias], group_id,
                         final_object_id);
    t->stats.recovery_checkpoints_sent++;
  }
  track->checkpoint_initialized = true;
  track->checkpoint_group_id = group_id;
  track->last_checkpoint_object_id = final_object_id;
  return succeeded;
}

static transport_publish_result_t
transport_publish_flush_grouped_ex(transport_t *t) {
  if (t->fec_buf_len == 0)
    return TRANSPORT_PUBLISH_DELIVERED;
  transport_fec_track_state_t *track_state =
      find_fec_track_state(t, &t->fec_track_id, true);
  if (!track_state)
    return TRANSPORT_PUBLISH_ERROR;
  moq_object_t obj = {.track_id = t->fec_track_id,
                      .group_id = 0,
                      .object_id = track_state->next_object_id,
                      .data = t->fec_buf,
                      .size = t->fec_buf_len,
                      .is_keyframe = false,
                      .priority = t->fec_priority};
  t->fec_in_flush = true;
  transport_publish_result_t result = transport_publish_impl(t, &obj);
  t->fec_in_flush = false;
  if (result != TRANSPORT_PUBLISH_DELIVERED &&
      result != TRANSPORT_PUBLISH_NO_RECIPIENTS)
    return result;
  track_state->next_object_id++;
  track_state->has_objects = true;
  t->fec_buf_len = 0;
  t->fec_first_pkt_time = 0;
  t->fec_pkt_count = 0;
  if ((track_state->track_id.flags & MOQ_TRACK_FLAG_FEC_RATELESS) != 0 &&
      track_state->next_object_id % QLINQ_RECOVERY_WINDOW_OBJECTS == 0) {
    uint64_t first_object_id =
        track_state->next_object_id - QLINQ_RECOVERY_WINDOW_OBJECTS;
    (void)emit_rolling_checkpoint(t, track_state, 0, first_object_id,
                                  track_state->next_object_id - 1U);
  }
  return TRANSPORT_PUBLISH_DELIVERED;
}

bool transport_publish_flush_grouped(transport_t *t) {
  transport_publish_result_t result = transport_publish_flush_grouped_ex(t);
  return result == TRANSPORT_PUBLISH_DELIVERED ||
         result == TRANSPORT_PUBLISH_NO_RECIPIENTS;
}

bool transport_publish_finish_grouped(transport_t *t,
                                      const moq_track_id_t *track_id,
                                      uint64_t *final_object_id,
                                      bool *has_objects) {
  if (!t || !track_id || !final_object_id || !has_objects)
    return false;
  if (t->fec_buf_len > 0 &&
      transport_track_id_equal(&t->fec_track_id, track_id) &&
      !transport_publish_flush_grouped(t))
    return false;
  transport_fec_track_state_t *state = find_fec_track_state(t, track_id, false);
  *has_objects = state && state->has_objects;
  *final_object_id = *has_objects ? state->next_object_id - 1U : 0;
  return true;
}

static transport_publish_result_t
transport_publish_impl(transport_t *t, const moq_object_t *obj) {
  if (!transport_owner_ok(t) || !obj ||
      !transport_track_id_valid(&obj->track_id) ||
      (obj->size > 0 && !obj->data))
    return TRANSPORT_PUBLISH_INVALID;

  size_t fec_limit = publication_fec_limit(t, &obj->track_id);

  /* route to grouping buffer if it's data and we're not flushing */
  if (obj->track_id.type == MOQ_TRACK_DATA && !t->fec_in_flush) {
    bool use_fec = false;
    if (t->is_server) {
      for (size_t c = 0; c < t->conn_count; c++) {
        transport_conn_t *conn = t->conns[c];
        if (conn && conn->quic && conn->protocol_ready && conn->authenticated &&
            quicly_get_state(conn->quic) < QUICLY_STATE_CLOSING) {
          const track_subscription_t *subscription =
              transport_subscriptions_find_const(&conn->subscriptions,
                                                 &obj->track_id);
          if (subscription) {
            transport_track_profile_t sub_profile =
                transport_track_profile(&subscription->track_id);
            use_fec = sub_profile.fec_enabled || sub_profile.fec_rateless;
          }
          if (use_fec)
            break;
        }
      }
    } else if (t->client_conn && t->client_conn->protocol_ready &&
               t->client_conn->authenticated) {
      transport_conn_t *conn = t->client_conn;
      const track_subscription_t *subscription =
          transport_subscriptions_find_const(&conn->subscriptions,
                                             &obj->track_id);
      if (subscription) {
        transport_track_profile_t sub_profile =
            transport_track_profile(&subscription->track_id);
        use_fec = sub_profile.fec_enabled || sub_profile.fec_rateless;
      }
    }

    if (use_fec) {
      size_t group_limit = fec_limit < 16384U ? fec_limit : 16384U;
      if (obj->size > TRANSPORT_MAX_FEC_RECORD_SIZE || fec_limit < 2U ||
          obj->size > fec_limit - 2U)
        return TRANSPORT_PUBLISH_INVALID;

      if (t->fec_buf_len > 0 &&
          (!transport_track_id_equal(&t->fec_track_id, &obj->track_id) ||
           t->fec_priority != obj->priority)) {
        transport_publish_result_t result =
            transport_publish_flush_grouped_ex(t);
        if (result == TRANSPORT_PUBLISH_BACKPRESSURE)
          return result;
        if (result != TRANSPORT_PUBLISH_DELIVERED)
          return TRANSPORT_PUBLISH_ERROR;
      }

      if (t->fec_buf_len > 0 &&
          (t->fec_pkt_count >= 4 || obj->size > group_limit - 2U ||
           t->fec_buf_len > group_limit - 2U - obj->size)) {
        transport_publish_result_t result =
            transport_publish_flush_grouped_ex(t);
        if (result == TRANSPORT_PUBLISH_BACKPRESSURE)
          return result;
        if (result != TRANSPORT_PUBLISH_DELIVERED)
          return TRANSPORT_PUBLISH_ERROR;
      }

      uint64_t now = ptls_get_time.cb(&ptls_get_time);
      if (t->fec_buf_len == 0) {
        t->fec_first_pkt_time = now;
        t->fec_track_id = obj->track_id;
        t->fec_priority = obj->priority;
      }

      if (obj->size > SIZE_MAX - 2 - t->fec_buf_len)
        return TRANSPORT_PUBLISH_INVALID;
      size_t needed = t->fec_buf_len + 2 + obj->size;
      if (needed > t->fec_buf_cap) {
        size_t new_cap = t->fec_buf_cap == 0 ? 4096 : t->fec_buf_cap * 2;
        if (new_cap < t->fec_buf_cap)
          return TRANSPORT_PUBLISH_ERROR;
        while (new_cap < needed) {
          if (new_cap > SIZE_MAX / 2)
            return TRANSPORT_PUBLISH_ERROR;
          new_cap *= 2;
        }
        uint8_t *new_buf = realloc(t->fec_buf, new_cap);
        if (!new_buf) {
          return TRANSPORT_PUBLISH_ERROR;
        }
        t->fec_buf = new_buf;
        t->fec_buf_cap = new_cap;
      }

      uint16_t len_be = htons((uint16_t)obj->size);
      memcpy(t->fec_buf + t->fec_buf_len, &len_be, 2);
      memcpy(t->fec_buf + t->fec_buf_len + 2, obj->data, obj->size);
      t->fec_buf_len = needed;
      t->fec_pkt_count++;

      if (t->fec_pkt_count >= 4 || t->fec_buf_len >= group_limit) {
        transport_publish_result_t result =
            transport_publish_flush_grouped_ex(t);
        if (result == TRANSPORT_PUBLISH_BACKPRESSURE)
          return TRANSPORT_PUBLISH_BUFFERED;
        return result == TRANSPORT_PUBLISH_DELIVERED
                   ? TRANSPORT_PUBLISH_DELIVERED
                   : TRANSPORT_PUBLISH_ERROR;
      }
      return TRANSPORT_PUBLISH_BUFFERED;
    }
  }

  transport_track_profile_t profile = transport_track_profile(&obj->track_id);

  /* route over reliable stream if requested by profile */
  if (profile.reliable) {
    if (obj->size > t->limits.max_reliable_object_size)
      return TRANSPORT_PUBLISH_INVALID;
    size_t active_count =
        t->is_server ? t->conn_count : (t->client_conn ? 1 : 0);
    size_t eligible = 0;
    size_t delivered = 0;
    bool failed = false;
    for (size_t i = 0; i < active_count; ++i) {
      transport_conn_t *conn = t->is_server ? t->conns[i] : t->client_conn;
      if (!conn || !conn->quic || !conn->protocol_ready ||
          !conn->authenticated ||
          quicly_get_state(conn->quic) >= QUICLY_STATE_CLOSING)
        continue;
      if (t->is_server && !transport_subscriptions_contains(
                              &conn->subscriptions, &obj->track_id))
        continue;
      eligible++;
      if (obj->size > conn->negotiated_limits.max_reliable_object_size) {
        failed = true;
        continue;
      }

      track_subscription_t *sub =
          transport_subscriptions_find(&conn->subscriptions, &obj->track_id);
      if (sub) {
        if (!sub->stream ||
            !quicly_sendstate_is_open(&sub->stream->sendstate)) {
          sub->stream = NULL;
          int err = quicly_open_stream(conn->quic, &sub->stream,
                                       1); /* 1 = unidirectional */
          if (err == 0 && sub->stream) {
            quicly_debug_printf(conn->quic,
                                "Opened QUIC Stream %" PRIu64
                                " for MoQ track alias %d",
                                sub->stream->stream_id, sub->alias);
          } else {
            transport_log(t, TRANSPORT_LOG_ERROR, "stream", conn->id, SIZE_MAX,
                          "failed to open reliable track stream: %d", err);
            failed = true;
            continue;
          }
        }

        uint8_t alias = sub->alias;
        if (!transport_stream_write_object_frame(sub->stream, alias, obj)) {
          failed = true;
          continue;
        }
      } else {
        if (!transport_send_unicast(t, conn, obj->data, obj->size)) {
          failed = true;
          continue;
        }
      }
      delivered++;
    }
    if (failed)
      return delivered > 0 ? TRANSPORT_PUBLISH_PARTIAL
                           : TRANSPORT_PUBLISH_ERROR;
    return eligible == 0 ? TRANSPORT_PUBLISH_NO_RECIPIENTS
                         : TRANSPORT_PUBLISH_DELIVERED;
  }

  /* audio, video, text tracks go over unreliable datagram frames with FEC */
  size_t data_size = obj->size;
  if (data_size == 0 || data_size > fec_limit)
    return TRANSPORT_PUBLISH_INVALID;
  size_t symbol_size = transport_get_datagram_symbol_size(t);
  size_t data_symbols = (data_size + symbol_size - 1) / symbol_size;
  if (data_symbols == 0)
    data_symbols = 1;

  bool protect_repair_cache = obj->track_id.type == MOQ_TRACK_DATA &&
                              profile.fec_rateless &&
                              checkpoint_cache_is_protected(t, &obj->track_id);
  if (protect_repair_cache && !transport_sent_cache_has_space(&t->sent_cache)) {
    t->stats.recovery_cache_backpressure++;
    return TRANSPORT_PUBLISH_BACKPRESSURE;
  }

  size_t active_count =
      t->is_server ? t->conn_count : (t->client_conn ? 1U : 0U);
  size_t eligible = 0;
  size_t delivered = 0;
  uint16_t maximum_sent_symbols = (uint16_t)data_symbols;
  bool partially_queued = false;
  transport_publish_result_t failure = TRANSPORT_PUBLISH_ERROR;

  for (size_t c = 0; c < active_count; c++) {
    transport_conn_t *conn = t->is_server ? t->conns[c] : t->client_conn;
    if (!conn || !conn->quic || !conn->protocol_ready || !conn->authenticated ||
        quicly_get_state(conn->quic) >= QUICLY_STATE_CLOSING ||
        (t->is_server && !transport_subscriptions_contains(&conn->subscriptions,
                                                           &obj->track_id)))
      continue;
    eligible++;
    if (obj->size > conn->negotiated_limits.max_fec_object_size) {
      failure = TRANSPORT_PUBLISH_INVALID;
      continue;
    }
    uint16_t sent_symbols = 0;
    transport_publish_result_t result = publish_datagram_to_conn(
        t, conn, obj, &profile, symbol_size, data_symbols, &sent_symbols);
    if (sent_symbols > maximum_sent_symbols)
      maximum_sent_symbols = sent_symbols;
    if (result == TRANSPORT_PUBLISH_DELIVERED) {
      delivered++;
    } else if (result == TRANSPORT_PUBLISH_NO_RECIPIENTS) {
      eligible--;
    } else {
      if (result == TRANSPORT_PUBLISH_PARTIAL)
        partially_queued = true;
      if (result == TRANSPORT_PUBLISH_BACKPRESSURE)
        failure = TRANSPORT_PUBLISH_BACKPRESSURE;
    }
  }

  if ((delivered > 0 || partially_queued) &&
      obj->track_id.type == MOQ_TRACK_DATA &&
      !transport_sent_cache_store(&t->sent_cache, obj, maximum_sent_symbols,
                                  (uint16_t)data_symbols, (uint16_t)symbol_size,
                                  !protect_repair_cache))
    return delivered > 0 ? TRANSPORT_PUBLISH_PARTIAL : TRANSPORT_PUBLISH_ERROR;

  if (partially_queued || (delivered > 0 && delivered != eligible))
    return TRANSPORT_PUBLISH_PARTIAL;
  if (delivered == 0)
    return eligible == 0 ? TRANSPORT_PUBLISH_NO_RECIPIENTS : failure;
  return TRANSPORT_PUBLISH_DELIVERED;
}

transport_publish_result_t transport_publish_ex(transport_t *t,
                                                const moq_object_t *obj) {
  if (!transport_owner_ok(t))
    return TRANSPORT_PUBLISH_INVALID;
  transport_publish_result_t result = transport_publish_impl(t, obj);
  switch (result) {
  case TRANSPORT_PUBLISH_DELIVERED:
    t->stats.publish_delivered++;
    break;
  case TRANSPORT_PUBLISH_BUFFERED:
    t->stats.publish_buffered++;
    break;
  case TRANSPORT_PUBLISH_NO_RECIPIENTS:
    t->stats.publish_no_recipients++;
    break;
  case TRANSPORT_PUBLISH_PARTIAL:
    t->stats.publish_partial++;
    break;
  case TRANSPORT_PUBLISH_BACKPRESSURE:
    t->stats.publish_backpressure++;
    break;
  case TRANSPORT_PUBLISH_INVALID:
    t->stats.publish_invalid++;
    break;
  case TRANSPORT_PUBLISH_ERROR:
    t->stats.publish_errors++;
    break;
  }
  return result;
}

bool transport_publish(transport_t *t, const moq_object_t *obj) {
  transport_publish_result_t result = transport_publish_ex(t, obj);
  return result == TRANSPORT_PUBLISH_DELIVERED ||
         result == TRANSPORT_PUBLISH_BUFFERED ||
         result == TRANSPORT_PUBLISH_NO_RECIPIENTS;
}

bool transport_finish_track(transport_t *t, moq_track_id_t track_id) {
  if (!transport_owner_ok(t) || !transport_track_id_valid(&track_id) ||
      track_id.type != MOQ_TRACK_DATA ||
      (track_id.flags & MOQ_TRACK_FLAG_FEC_RATELESS) == 0)
    return false;

  uint64_t final_object_id = 0;
  bool has_objects = false;
  if (!transport_publish_finish_grouped(t, &track_id, &final_object_id,
                                        &has_objects))
    return false;
  if (!has_objects)
    return true;

  size_t active_count = t->is_server ? t->conn_count : (t->client_conn ? 1 : 0);
  bool found = false;
  bool succeeded = true;
  for (size_t i = 0; i < active_count; i++) {
    transport_conn_t *conn = t->is_server ? t->conns[i] : t->client_conn;
    if (!conn || !conn->quic || !conn->protocol_ready || !conn->authenticated ||
        !conn->stream || !quicly_sendstate_is_open(&conn->stream->sendstate) ||
        quicly_get_state(conn->quic) >= QUICLY_STATE_CLOSING)
      continue;
    uint8_t alias = 0;
    if (transport_subscriptions_find_alias(&conn->subscriptions, &track_id,
                                           &alias) != 0)
      continue;
    found = true;
    if (transport_stream_write_track_end_frame(conn->stream, alias, 0,
                                               final_object_id)) {
      t->stats.track_ends_sent++;
      if ((conn->peer_capabilities & QLINQ_WIRE_CAP_RECOVERY_CHECKPOINTS) !=
          0) {
        if (!conn->checkpoint_acks[alias].participating)
          transport_publish_checkpoint_member_added(t, conn, &track_id, alias);
        checkpoint_mark_sent(&conn->checkpoint_acks[alias], 0, final_object_id);
      }
    } else {
      succeeded = false;
    }
  }
  transport_fec_track_state_t *state =
      find_fec_track_state(t, &track_id, false);
  if (state) {
    state->checkpoint_initialized = true;
    state->checkpoint_group_id = 0;
    state->last_checkpoint_object_id = final_object_id;
  }
  return !found || succeeded;
}
