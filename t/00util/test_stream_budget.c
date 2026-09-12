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

int main(void) {
  int failed = entry_limit_and_control_failure() ||
               byte_limits_and_recovery() || endpoint_vector_limit() ||
               vector_capacity_compaction() || configurable_limits();
  if (!failed)
    puts("===STREAM BUDGET OK===");
  return failed;
}
