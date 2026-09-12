#include "quicly/streambuf.h"
#include "transport_config.h"
#include "transport_internal.h"
#include "transport_protocol.h"
#include "transport_stream.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(test)                                                            \
  do {                                                                         \
    if (!(test)) {                                                             \
      fprintf(stderr, "stream budget line %d: %s\n", __LINE__, #test);         \
      failed = 1;                                                              \
      goto cleanup;                                                            \
    }                                                                          \
  } while (0)

static void ignore_event(void *data, const transport_event_t *event) {
  (void)data;
  (void)event;
}

static transport_t *fixture(void) {
  transport_config_t config = {.bind_hosts = {"127.0.0.1"},
                               .num_bind_hosts = 1,
                               .remote_hosts = {"127.0.0.1"},
                               .num_remote_hosts = 1,
                               .port = 19869,
                               .allow_insecure_peer = true,
                               .callback = ignore_event};
  return transport_create(&config);
}

/* Invoke the actual QUIC stream destruction callbacks while the transport's
 * accounting still exists. These fixtures have no packet I/O or assemblers. */
static bool dispose(transport_t *t) {
  if (!t)
    return false;
  transport_conn_t *conn = t->client_conn;
  if (conn) {
    quicly_free(conn->quic);
    transport_subscriptions_destroy(&conn->send_subscriptions);
    transport_subscriptions_destroy(&conn->receive_subscriptions);
    free(conn);
    t->client_conn = NULL;
  }
  bool released = t->stats.stream_egress_bytes == 0 &&
                  t->stats.stream_egress_frames == 0 &&
                  t->stats.stream_egress_vector_capacity == 0;
  transport_destroy(t);
  return released;
}

static bool acknowledge(quicly_stream_t *stream, size_t bytes) {
  uint64_t first = stream->sendstate.acked.ranges[0].end;
  quicly_sendstate_sent_t sent = {.start = first, .end = first + bytes};
  if (stream->sendstate.size_inflight < sent.end)
    stream->sendstate.size_inflight = sent.end;
  size_t shift = 0;
  if (quicly_sendstate_acked(&stream->sendstate, &sent, &shift) != 0 ||
      shift != bytes)
    return false;
  stream->callbacks->on_send_shift(stream, shift);
  return true;
}

static int entry_limit_and_control_failure(void) {
  int failed = 0;
  transport_t *t = fixture();
  CHECK(t && t->client_conn && t->client_conn->stream);
  quicly_stream_t *stream = t->client_conn->stream;
  size_t accepted = 0;
  while (accepted < 1024 &&
         transport_stream_write_frame(stream, QLINQ_WIRE_UNICAST, "x", 1))
    accepted++;
  CHECK(accepted > 0 && accepted < TRANSPORT_STREAM_MAX_FRAMES);
  CHECK(quicly_get_state(stream->conn) < QUICLY_STATE_CLOSING);
  size_t retained = t->stats.stream_egress_bytes;
  size_t vectors = t->stats.stream_egress_vector_capacity;
  CHECK(acknowledge(stream, 1));
  CHECK(t->stats.stream_egress_bytes == retained &&
        t->stats.stream_egress_frames == accepted);
  CHECK(!transport_stream_write_frame(stream, QLINQ_WIRE_UNICAST, "x", 1));
  CHECK(acknowledge(stream, QLINQ_WIRE_FRAME_HEADER_SIZE));
  CHECK(t->stats.stream_egress_bytes < retained &&
        t->stats.stream_egress_vector_capacity == vectors);
  CHECK(transport_stream_write_frame(stream, QLINQ_WIRE_UNICAST, "x", 1));
  size_t controls = 0;
  while (controls < TRANSPORT_STREAM_MAX_FRAMES &&
         transport_stream_write_track_checkpoint_frame(stream, 1, 0, controls,
                                                       controls, false))
    controls++;
  CHECK(controls > 0 && accepted + controls <= TRANSPORT_STREAM_MAX_FRAMES);
  CHECK(quicly_get_state(stream->conn) >= QUICLY_STATE_CLOSING &&
        t->stats.stream_control_failures == 1 &&
        t->stats.resource_limit_errors == 1);
  CHECK(QUICLY_ERROR_GET_ERROR_CODE(
            quicly_get_close_reason(stream->conn, NULL, NULL, NULL)) == 0x102);
cleanup:
  if (!dispose(t))
    failed = 1;
  return failed;
}

static int byte_limits_and_recovery(void) {
  int failed = 0;
  transport_t *t = fixture();
  uint8_t *payload = malloc(TRANSPORT_MAX_RELIABLE_OBJECT_SIZE);
  CHECK(t && t->client_conn && payload);
  memset(payload, 0x5a, TRANSPORT_MAX_RELIABLE_OBJECT_SIZE);
  transport_conn_t *conn = t->client_conn;
  conn->authenticated = conn->protocol_ready = true;
  conn->negotiated_limits = t->limits;
  moq_track_id_t track = {.type = MOQ_TRACK_DATA,
                          .flags = MOQ_TRACK_FLAG_RELIABLE,
                          .name = "pressure"};
  CHECK(transport_subscriptions_add(&conn->send_subscriptions, track.type,
                                    track.flags, track.name, 1));
  moq_object_t object = {.track_id = track,
                         .data = payload,
                         .size = TRANSPORT_MAX_RELIABLE_OBJECT_SIZE};
  CHECK(transport_publish_ex(t, &object) == TRANSPORT_PUBLISH_DELIVERED);
  quicly_stream_t *stream =
      transport_subscriptions_find(&conn->send_subscriptions, &track)->stream;
  CHECK(stream);
  CHECK(transport_publish_ex(t, &object) == TRANSPORT_PUBLISH_BACKPRESSURE);
  size_t retained = t->stats.stream_egress_bytes;
  CHECK(retained <= TRANSPORT_STREAM_MAX_BYTES);
  size_t frame_size = QLINQ_WIRE_FRAME_HEADER_SIZE +
                      QLINQ_WIRE_TRACK_OBJECT_HEADER_SIZE + object.size;
  CHECK(acknowledge(stream, frame_size / 2));
  CHECK(t->stats.stream_egress_bytes == retained);
  CHECK(transport_publish_ex(t, &object) == TRANSPORT_PUBLISH_BACKPRESSURE);
  CHECK(acknowledge(stream, frame_size - frame_size / 2));
  CHECK(t->stats.stream_egress_bytes == 0 &&
        t->stats.stream_egress_vector_capacity == 0);
  CHECK(transport_publish_ex(t, &object) == TRANSPORT_PUBLISH_DELIVERED);
  /* Open independent streams so endpoint pressure cannot be mistaken for the
   * per-stream byte or frame limits. No socket service/ACKs occur in this part.
   */
  size_t streams = 1;
  while (streams < 32) {
    CHECK(quicly_open_stream(conn->quic, &stream, 1) == 0);
    if (!transport_stream_write_object_frame(stream, 1, &object))
      break;
    streams++;
  }
  CHECK(streams >= 8 && streams < 32);
  CHECK(t->stats.stream_egress_bytes <= TRANSPORT_STREAM_ENDPOINT_MAX_BYTES);
  CHECK(quicly_get_state(conn->quic) < QUICLY_STATE_CLOSING);
  CHECK(transport_stream_write_track_checkpoint_frame(conn->stream, 1, 0, 0, 0,
                                                      false));
cleanup:
  free(payload);
  if (!dispose(t))
    failed = 1;
  return failed;
}

static int endpoint_vector_limit(void) {
  int failed = 0;
  transport_t *t = fixture();
  CHECK(t && t->client_conn);
  size_t accepted = 0;
  for (size_t n = 0; n < 32; n++) {
    quicly_stream_t *stream;
    CHECK(quicly_open_stream(t->client_conn->quic, &stream, 1) == 0);
    size_t before = accepted;
    for (size_t i = 0; i < TRANSPORT_STREAM_MAX_FRAMES; i++) {
      if (!transport_stream_write_frame(stream, QLINQ_WIRE_TRACK_OBJECT, "x",
                                        1))
        break;
      accepted++;
    }
    if (accepted == before)
      break;
  }
  CHECK(accepted > TRANSPORT_STREAM_MAX_FRAMES &&
        accepted < TRANSPORT_STREAM_ENDPOINT_MAX_VECTORS);
  CHECK(t->stats.stream_egress_bytes < 1024 * 1024 &&
        t->stats.stream_egress_vector_capacity <=
            TRANSPORT_STREAM_ENDPOINT_MAX_VECTORS);
  CHECK(transport_stream_write_track_checkpoint_frame(t->client_conn->stream, 1,
                                                      0, 0, 0, false));
cleanup:
  if (!dispose(t))
    failed = 1;
  return failed;
}

static int vector_capacity_compaction(void) {
  int failed = 0;
  transport_t *t = fixture();
  CHECK(t && t->client_conn && t->client_conn->stream);
  quicly_stream_t *stream = t->client_conn->stream;
  const size_t frame_size = QLINQ_WIRE_FRAME_HEADER_SIZE + 1;
  for (size_t i = 0; i < 129; i++)
    CHECK(transport_stream_write_frame(stream, QLINQ_WIRE_UNICAST, "x", 1));
  CHECK(t->stats.stream_egress_frames == 129 &&
        t->stats.stream_egress_vector_capacity == 256);
  CHECK(acknowledge(stream, 120 * frame_size));
  CHECK(t->stats.stream_egress_frames == 9 &&
        t->stats.stream_egress_vector_capacity == 16);
  CHECK(acknowledge(stream, 9 * frame_size));
  CHECK(t->stats.stream_egress_frames == 0 &&
        t->stats.stream_egress_vector_capacity == 0);
cleanup:
  if (!dispose(t))
    failed = 1;
  return failed;
}

static int configurable_limits(void) {
  int failed = 0;
  transport_t *t = NULL;
  transport_limits_t requested = {
      .max_reliable_object_size = 64U * 1024U,
      .max_stream_egress_bytes = 128U * 1024U + 1024U,
      .max_total_stream_egress_bytes =
          128U * 1024U + 1024U +
          TRANSPORT_STREAM_ENDPOINT_CONTROL_BYTE_RESERVE};
  transport_limits_t resolved;
  char error[256];
  CHECK(transport_limits_resolve(&requested, &resolved, error, sizeof(error)));
  requested.max_stream_egress_bytes--;
  CHECK(!transport_limits_resolve(&requested, &resolved, error, sizeof(error)));
  requested.max_stream_egress_bytes++;
  requested.max_total_stream_egress_bytes--;
  CHECK(!transport_limits_resolve(&requested, &resolved, error, sizeof(error)));
  requested.max_total_stream_egress_bytes++;
  transport_config_t config = {.bind_hosts = {"127.0.0.1"},
                               .num_bind_hosts = 1,
                               .remote_hosts = {"127.0.0.1"},
                               .num_remote_hosts = 1,
                               .port = 19869,
                               .allow_insecure_peer = true,
                               .callback = ignore_event,
                               .limits = requested};
  t = transport_create(&config);
  CHECK(t && t->client_conn && t->client_conn->stream);
  quicly_stream_t *stream;
  CHECK(quicly_open_stream(t->client_conn->quic, &stream, 1) == 0);
  uint8_t payload[64U * 1024U] = {0};
  CHECK(transport_stream_write_frame(stream, QLINQ_WIRE_UNICAST, payload,
                                     sizeof(payload)));
  CHECK(transport_stream_write_frame(stream, QLINQ_WIRE_UNICAST, payload,
                                     sizeof(payload)));
  CHECK(!transport_stream_write_frame(stream, QLINQ_WIRE_UNICAST, payload,
                                      sizeof(payload)));
  CHECK(t->stats.stream_egress_bytes <= requested.max_stream_egress_bytes);
  CHECK(acknowledge(stream,
                    2U * (sizeof(payload) + QLINQ_WIRE_FRAME_HEADER_SIZE)));
  CHECK(t->stats.stream_egress_bytes == 0);
  CHECK(transport_stream_write_frame(stream, QLINQ_WIRE_UNICAST, payload,
                                     sizeof(payload)));
cleanup:
  if (t && !dispose(t))
    failed = 1;
  return failed;
}

static int retained_nack_retries(bool rateless) {
  int failed = 0;
  transport_t *t = fixture();
  CHECK(t && t->client_conn && t->client_conn->stream);
  transport_conn_t *conn = t->client_conn;
  quicly_stream_t *stream = conn->stream;
  quicly_sendbuf_t *sb =
      &((transport_stream_ctx_t *)stream->data)->streambuf.egress;
  uint8_t flags =
      MOQ_TRACK_FLAG_FEC_ENABLED | (rateless ? MOQ_TRACK_FLAG_FEC_RATELESS : 0);
  conn->peer_capabilities |= QLINQ_WIRE_CAP_RATELESS_REPAIR;
  moq_track_id_t track = {
      .type = MOQ_TRACK_DATA, .flags = flags, .name = "nack-one"};
  CHECK(transport_get_effective_repair_mode(t, conn, &track) ==
        (rateless ? TRANSPORT_REPAIR_MODE_RATELESS
                  : TRANSPORT_REPAIR_MODE_INDEXED));
  CHECK(transport_subscriptions_add(&conn->receive_subscriptions,
                                    MOQ_TRACK_DATA, flags, "nack-one", 1));
  CHECK(transport_subscriptions_add(&conn->receive_subscriptions,
                                    MOQ_TRACK_DATA, flags, "nack-two", 2));
  CHECK(transport_protocol_send_nack(conn, 1, 7, 11, NULL, 0, true));
  size_t first_size = sb->bytes_written;
  CHECK(t->stats.stream_egress_frames == 1);
  /* Repeated timer callbacks cannot multiply a request which has not had a
   * chance to leave this reliable stream. No packet service occurs here. */
  for (size_t i = 0; i < 512; i++) {
    CHECK(transport_protocol_send_nack(conn, 1, 7, 11, NULL, 0, true));
    CHECK(t->stats.stream_egress_frames == 1 &&
          sb->bytes_written == first_size);
  }
  CHECK(t->stats.repair_requests_sent == 1);
  CHECK(t->stats.repair_requests_coalesced == 512 &&
        t->stats.repair_requests_deferred == 0);
  fprintf(stderr,
          "%s: 512 unsent retries retained %zu frame, %zu vector slots, %zu "
          "bytes\n",
          rateless ? "rateless" : "fixed", t->stats.stream_egress_frames,
          t->stats.stream_egress_vector_capacity, t->stats.stream_egress_bytes);
  CHECK(quicly_get_state(conn->quic) < QUICLY_STATE_CLOSING);
  /* QUIC owns reliable retransmission until the request is acknowledged.
   * Repeated application timers must not append another identical frame even
   * when packet service has marked every queued byte as transmitted. */
  for (size_t i = 0; i < 512; i++) {
    stream->sendstate.size_inflight = sb->bytes_written;
    CHECK(transport_protocol_send_nack(conn, 1, 7, 11, NULL, 0, true));
    CHECK(t->stats.stream_egress_frames == 1 &&
          sb->bytes_written == first_size);
  }
  CHECK(t->stats.repair_requests_sent == 1 &&
        t->stats.repair_requests_coalesced == 1024);
  /* A partial ACK retains the entire original frame and must still coalesce. */
  CHECK(acknowledge(stream, 1));
  CHECK(transport_protocol_send_nack(conn, 1, 7, 11, NULL, 0, true));
  CHECK(t->stats.stream_egress_frames == 1);
  CHECK(acknowledge(stream, first_size - 1));
  CHECK(t->stats.stream_egress_bytes == 0 &&
        t->stats.stream_egress_vector_capacity == 0);
  /* The request arrived, but its repair response can be lost. After QUIC
   * releases that request, the existing application retry can enqueue again. */
  CHECK(transport_protocol_send_nack(conn, 1, 7, 11, NULL, 0, true));
  CHECK(t->stats.repair_requests_sent == 2 &&
        t->stats.stream_egress_frames == 1);
  stream->sendstate.size_inflight = sb->bytes_written;
  CHECK(acknowledge(stream, first_size));
  CHECK(t->stats.stream_egress_bytes == 0 &&
        t->stats.stream_egress_vector_capacity == 0);
  CHECK(transport_protocol_send_nack(conn, 1, 7, 11, NULL, 0, true));
  CHECK(t->stats.repair_requests_sent == 3);
  /* Different aliases, groups, objects, request scopes and missing symbols
   * are independent requests, even when none has been transmitted. */
  CHECK(transport_protocol_send_nack(conn, 2, 7, 11, NULL, 0, true));
  CHECK(transport_protocol_send_nack(conn, 1, 8, 11, NULL, 0, true));
  CHECK(transport_protocol_send_nack(conn, 1, 7, 12, NULL, 0, true));
  uint16_t missing[] = {3, 5};
  CHECK(transport_protocol_send_nack(conn, 1, 7, 11, rateless ? NULL : missing,
                                     2, false));
  missing[1] = 6;
  CHECK(transport_protocol_send_nack(conn, 1, 7, 11, rateless ? NULL : missing,
                                     rateless ? 3 : 2, false));
  CHECK(t->stats.repair_requests_sent == 8 &&
        t->stats.stream_egress_frames == 6);
cleanup:
  if (!dispose(t))
    failed = 1;
  return failed;
}

/* QUIC can ACK a later STREAM range before its prefix arrives. That frame
 * remains retained and the peer cannot parse it until the prefix is repaired.
 */
static int retained_nack_ack_gap(bool rateless) {
  int failed = 0;
  transport_t *t = fixture();
  CHECK(t && t->client_conn && t->client_conn->stream);
  transport_conn_t *conn = t->client_conn;
  conn->peer_capabilities |= QLINQ_WIRE_CAP_RATELESS_REPAIR;
  uint8_t flags =
      MOQ_TRACK_FLAG_FEC_ENABLED | (rateless ? MOQ_TRACK_FLAG_FEC_RATELESS : 0);
  CHECK(transport_subscriptions_add(&conn->receive_subscriptions,
                                    MOQ_TRACK_DATA, flags, "ack-gap", 1));
  moq_track_id_t track = {
      .type = MOQ_TRACK_DATA, .flags = flags, .name = "ack-gap"};
  CHECK(transport_get_effective_repair_mode(t, conn, &track) ==
        (rateless ? TRANSPORT_REPAIR_MODE_RATELESS
                  : TRANSPORT_REPAIR_MODE_INDEXED));
  quicly_stream_t *stream = conn->stream;
  quicly_sendbuf_t *sb =
      &((transport_stream_ctx_t *)stream->data)->streambuf.egress;
  CHECK(transport_protocol_send_nack(conn, 1, 7, 11, NULL, 0, true));
  size_t first_size = sb->bytes_written;
  CHECK(transport_protocol_send_nack(conn, 1, 7, 12, NULL, 0, true));
  stream->sendstate.size_inflight = sb->bytes_written;
  quicly_sendstate_sent_t later = {.start = first_size,
                                   .end = sb->bytes_written};
  size_t shift = 0;
  CHECK(quicly_sendstate_acked(&stream->sendstate, &later, &shift) == 0 &&
        shift == 0);
  stream->callbacks->on_send_shift(stream, shift);
  CHECK(transport_protocol_send_nack(conn, 1, 7, 12, NULL, 0, true));
  CHECK(t->stats.stream_egress_frames == 2 &&
        t->stats.repair_requests_sent == 2);
  CHECK(transport_protocol_send_nack(conn, 1, 7, 11, NULL, 0, true));
  CHECK(t->stats.stream_egress_frames == 2 &&
        t->stats.repair_requests_coalesced == 2);
  quicly_sendstate_sent_t first = {.start = 0, .end = first_size};
  CHECK(quicly_sendstate_acked(&stream->sendstate, &first, &shift) == 0 &&
        shift == sb->bytes_written);
  stream->callbacks->on_send_shift(stream, shift);
  CHECK(t->stats.stream_egress_frames == 0 &&
        t->stats.stream_egress_bytes == 0 &&
        t->stats.stream_egress_vector_capacity == 0);
  CHECK(transport_protocol_send_nack(conn, 1, 7, 12, NULL, 0, true));
  CHECK(t->stats.stream_egress_frames == 1 &&
        t->stats.repair_requests_sent == 3);
cleanup:
  if (!dispose(t))
    failed = 1;
  return failed;
}

static int repair_pressure(bool endpoint, bool rateless) {
  int failed = 0;
  transport_t *t = fixture();
  CHECK(t && t->client_conn && t->client_conn->stream);
  transport_conn_t *conn = t->client_conn;
  conn->peer_capabilities |= QLINQ_WIRE_CAP_RATELESS_REPAIR;
  uint8_t flags =
      MOQ_TRACK_FLAG_FEC_ENABLED | (rateless ? MOQ_TRACK_FLAG_FEC_RATELESS : 0);
  CHECK(transport_subscriptions_add(&conn->receive_subscriptions,
                                    MOQ_TRACK_DATA, flags, "pressure", 1));
  moq_track_id_t track = {
      .type = MOQ_TRACK_DATA, .flags = flags, .name = "pressure"};
  CHECK(transport_get_effective_repair_mode(t, conn, &track) ==
        (rateless ? TRANSPORT_REPAIR_MODE_RATELESS
                  : TRANSPORT_REPAIR_MODE_INDEXED));
  quicly_stream_t *release = conn->stream;
  if (endpoint) {
    /* Fill independent streams to exhaust endpoint capacity while the actual
     * control stream is empty. This distinguishes endpoint and stream caps. */
    size_t total = 0;
    for (unsigned n = 0; n < 32; n++) {
      quicly_stream_t *stream;
      CHECK(quicly_open_stream(conn->quic, &stream, 1) == 0);
      if (n == 0)
        release = stream;
      size_t before = total;
      while (transport_stream_write_frame(stream, QLINQ_WIRE_UNICAST, "x", 1))
        total++;
      if (total == before)
        break;
    }
    CHECK(total > TRANSPORT_STREAM_MAX_FRAMES);
  } else {
    size_t total = 0;
    while (
        transport_stream_write_frame(conn->stream, QLINQ_WIRE_UNICAST, "x", 1))
      total++;
    CHECK(total ==
          TRANSPORT_STREAM_MAX_FRAMES - TRANSPORT_STREAM_CONTROL_FRAME_RESERVE);
  }
  size_t bytes = t->stats.stream_egress_bytes;
  size_t frames = t->stats.stream_egress_frames;
  size_t vectors = t->stats.stream_egress_vector_capacity;
  /* Repair timers own retry state. Queue pressure must neither consume the
   * essential-control reserve nor turn an unanswered request into a close. */
  for (unsigned n = 0; n < 512; n++) {
    CHECK(!transport_protocol_send_nack(conn, 1, 7, 11, NULL, 0, true));
    CHECK(t->stats.stream_egress_bytes == bytes &&
          t->stats.stream_egress_frames == frames &&
          t->stats.stream_egress_vector_capacity == vectors);
    CHECK(quicly_get_state(conn->quic) < QUICLY_STATE_CLOSING);
  }
  CHECK(t->stats.repair_requests_sent == 0 &&
        t->stats.repair_requests_deferred == 512 &&
        t->stats.stream_control_failures == 0 &&
        t->stats.resource_limit_errors == 0);
  CHECK(transport_stream_write_track_checkpoint_frame(conn->stream, 1, 7, 0, 11,
                                                      false));
  quicly_sendbuf_t *sb =
      &((transport_stream_ctx_t *)release->data)->streambuf.egress;
  CHECK(acknowledge(release, sb->bytes_written));
  CHECK(transport_protocol_send_nack(conn, 1, 7, 11, NULL, 0, true));
  CHECK(t->stats.repair_requests_sent == 1 &&
        t->stats.repair_requests_deferred == 512 &&
        t->stats.stream_control_failures == 0 &&
        t->stats.resource_limit_errors == 0);
  fprintf(stderr,
          "%s %s: 512 deferred requests, essential checkpoint accepted, retry "
          "after ACK accepted\n",
          endpoint ? "endpoint" : "stream", rateless ? "rateless" : "fixed");
cleanup:
  if (!dispose(t))
    failed = 1;
  return failed;
}

static bool receive_control(quicly_stream_t *stream, uint8_t type,
                            const uint8_t *payload, size_t payload_size) {
  uint8_t frame[128];
  size_t size = QLINQ_WIRE_FRAME_HEADER_SIZE + payload_size;
  if (size > sizeof(frame) ||
      qlinq_wire_encode_frame_header(frame, sizeof(frame), type, payload_size,
                                     TRANSPORT_WIRE_MAX_STREAM_PAYLOAD) !=
          QLINQ_WIRE_OK)
    return false;
  memcpy(frame + QLINQ_WIRE_FRAME_HEADER_SIZE, payload, payload_size);
  size_t received = size;
  if (quicly_recvstate_update(&stream->recvstate, stream->recvstate.data_off,
                              &received, 0, 32) != 0 ||
      received != size)
    return false;
  stream->callbacks->on_receive(stream, 0, frame, size);
  if (quicly_get_state(stream->conn) >= QUICLY_STATE_CLOSING) {
    const char *reason = NULL;
    (void)quicly_get_close_reason(stream->conn, NULL, &reason, NULL);
    fprintf(stderr, "control receive closed: %s\n",
            reason ? reason : "unknown");
    return false;
  }
  return true;
}

static int checkpoint_retires_redundant_recovery(void) {
  int failed = 0;
  transport_t *t = fixture();
  CHECK(t && t->client_conn && t->client_conn->stream);
  transport_conn_t *conn = t->client_conn;
  conn->authenticated = conn->protocol_ready = true;
  conn->negotiated_limits = t->limits;
  conn->hello_received = true;
  conn->peer_capabilities |= QLINQ_WIRE_CAP_RECOVERY_CHECKPOINTS;
  CHECK(transport_subscriptions_add(&conn->receive_subscriptions,
                                    MOQ_TRACK_DATA, MOQ_TRACK_FLAG_FEC_RATELESS,
                                    "completion", 7));
  transport_object_gap_state_t *gap = transport_object_gap(conn, 7);
  gap->group_id = 3;
  gap->pending_base = 10;
  gap->pending_mask = 7;
  gap->last_seen = gap->largest_delivered = 11;
  gap->seen_initialized = gap->delivered_initialized = true;
  gap->delivered_mask[0] = 3;
  /* Covered, future, other-track and other-group partial objects coexist. */
  for (unsigned i = 0; i < 4; i++) {
    frame_assembler_t *a = &conn->assemblers[i];
    CHECK(transport_grow_assembler(t, a, 2, 32));
    a->track_id = i == 2 ? 8 : 7;
    a->group_id = i == 3 ? 4 : 3;
    a->object_id = i == 1 ? 13 : 11;
    a->total_symbols = 2;
  }
  size_t memory = t->assembler_memory_bytes;
  uint8_t payload[QLINQ_WIRE_TRACK_CHECKPOINT_SIZE];
  qlinq_wire_track_checkpoint_t checkpoint = {
      .alias = 7, .group_id = 3, .first_object_id = 10, .final_object_id = 11};
  CHECK(qlinq_wire_encode_track_checkpoint(payload, sizeof(payload),
                                           &checkpoint) == QLINQ_WIRE_OK);
  CHECK(receive_control(conn->stream, QLINQ_WIRE_TRACK_CHECKPOINT, payload,
                        sizeof(payload)));
  CHECK(t->stats.recovery_checkpoint_acks_sent == 1 && gap->pending_mask == 4);
  CHECK(conn->assemblers[0].total_symbols == 0 &&
        t->assembler_memory_bytes < memory);
  for (unsigned i = 1; i < 4; i++)
    CHECK(conn->assemblers[i].total_symbols == 2);
  /* A repeated completion also retires stale duplicates behind its watermark.
   */
  gap->pending_mask = 7;
  CHECK(transport_grow_assembler(t, &conn->assemblers[0], 2, 32));
  conn->assemblers[0].track_id = 7;
  conn->assemblers[0].group_id = 3;
  conn->assemblers[0].object_id = 11;
  conn->assemblers[0].total_symbols = 2;
  uint8_t end_payload[QLINQ_WIRE_TRACK_END_SIZE];
  qlinq_wire_track_end_t end = {
      .alias = 7, .group_id = 3, .final_object_id = 11};
  CHECK(qlinq_wire_encode_track_end(end_payload, sizeof(end_payload), &end) ==
        QLINQ_WIRE_OK);
  CHECK(receive_control(conn->stream, QLINQ_WIRE_TRACK_END, end_payload,
                        sizeof(end_payload)));
  CHECK(t->stats.recovery_checkpoint_acks_sent == 2 && gap->pending_mask == 4 &&
        conn->assemblers[0].total_symbols == 0);
  /* An incomplete next window retains recovery until the actual data arrives.
   */
  checkpoint.first_object_id = checkpoint.final_object_id = 12;
  CHECK(qlinq_wire_encode_track_checkpoint(payload, sizeof(payload),
                                           &checkpoint) == QLINQ_WIRE_OK);
  CHECK(receive_control(conn->stream, QLINQ_WIRE_TRACK_CHECKPOINT, payload,
                        sizeof(payload)));
  CHECK(t->stats.recovery_checkpoint_acks_sent == 2 && gap->pending_mask == 4);
  uint8_t datagram[QLINQ_WIRE_FEC_HEADER_SIZE + 3] = {0};
  qlinq_wire_fec_header_t header = {.alias = 7,
                                    .group_id = 3,
                                    .object_id = 12,
                                    .total_symbols = 1,
                                    .data_symbols = 1,
                                    .symbol_size = 3,
                                    .original_size = 3};
  CHECK(qlinq_wire_encode_fec_header(datagram, sizeof(datagram), &header) ==
        QLINQ_WIRE_OK);
  memcpy(datagram + QLINQ_WIRE_FEC_HEADER_SIZE, "abc", 3);
  t->receive_datagram.cb(&t->receive_datagram, conn->quic,
                         ptls_iovec_init(datagram, sizeof(datagram)));
  CHECK(t->stats.recovery_checkpoint_acks_sent == 3 && gap->pending_mask == 0);
  CHECK(t->stats.fec_objects_recovered == 1);
  for (unsigned i = 1; i < 4; i++)
    CHECK(conn->assemblers[i].total_symbols == 2);
cleanup:
  if (t) {
    for (size_t i = 0; i < t->limits.max_assemblers_per_connection; i++)
      transport_release_assembler(t, &t->client_conn->assemblers[i]);
    if (t->assembler_memory_bytes != 0 || !dispose(t))
      failed = 1;
  }
  return failed;
}

int main(void) {
  int failed = entry_limit_and_control_failure() ||
               byte_limits_and_recovery() || endpoint_vector_limit() ||
               vector_capacity_compaction() || configurable_limits() ||
               retained_nack_retries(false) || retained_nack_retries(true) ||
               retained_nack_ack_gap(false) || retained_nack_ack_gap(true) ||
               repair_pressure(false, false) || repair_pressure(false, true) ||
               repair_pressure(true, false) || repair_pressure(true, true) ||
               checkpoint_retires_redundant_recovery();
  if (!failed)
    puts("===STREAM BUDGET OK===");
  return failed;
}
