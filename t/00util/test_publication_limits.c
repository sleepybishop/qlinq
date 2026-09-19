#include "transport_fixture.h"
#include "transport_publish.h"
#include <stdio.h>

static void fill_queue(transport_conn_t *conn, size_t count) {
  /* Unknown application datagrams are discarded by the receiver. Queue them
   * directly in Quicly so the test also checks our capacity assumption. */
  uint8_t ignored = 0xff;
  ptls_iovec_t frame = ptls_iovec_init(&ignored, 1);
  while (quicly_get_num_datagram_frames_path(conn->quic, 0) < count) {
    size_t before = quicly_get_num_datagram_frames_path(conn->quic, 0);
    quicly_send_datagram_frames_path(conn->quic, 0, &frame, 1);
    assert(quicly_get_num_datagram_frames_path(conn->quic, 0) == before + 1);
  }
}

static void test_queue_boundary(void) {
  transport_fixture_t f;
  fixture_create(&f, 19932, NULL, NULL);
  moq_track_id_t track = {.type = MOQ_TRACK_VIDEO,
                          .flags = MOQ_TRACK_FLAG_FEC_ENABLED,
                          .name = "queue-boundary"};
  fixture_subscribe(&f, &f.client, track);
  transport_conn_t *conn = f.server.conn;
  uint8_t payload[2000] = {42};
  moq_object_t object = {
      .track_id = track, .data = payload, .size = sizeof(payload)};
  fill_queue(conn, 62);
  assert(transport_publish_ex(f.server.transport, &object) ==
         TRANSPORT_PUBLISH_BACKPRESSURE);
  assert(quicly_get_num_datagram_frames_path(conn->quic, 0) == 62);
  fill_queue(conn, 64);
  uint8_t ignored = 0xff;
  ptls_iovec_t frame = ptls_iovec_init(&ignored, 1);
  quicly_send_datagram_frames_path(conn->quic, 0, &frame, 1);
  assert(quicly_get_num_datagram_frames_path(conn->quic, 0) == 64);
  assert(QLINQ_PATH_DATAGRAM_QUEUE_CAPACITY == 64);
  for (size_t i = 0;
       i < 2000 && quicly_get_num_datagram_frames_path(conn->quic, 0); i++)
    fixture_tick(&f);
  assert(quicly_get_num_datagram_frames_path(conn->quic, 0) == 0);
  fill_queue(conn, 61);
  assert(transport_publish_ex(f.server.transport, &object) ==
         TRANSPORT_PUBLISH_DELIVERED);
  assert(quicly_get_num_datagram_frames_path(conn->quic, 0) == 64);
  fixture_receive(&f, &f.client, 1);
  assert(f.client.payload_size == sizeof(payload) &&
         memcmp(f.client.payload, payload, sizeof(payload)) == 0);
  fixture_destroy(&f);
}

static void test_partial_group_retry(void) {
  transport_fixture_t f;
  fixture_create(&f, 19933, NULL, NULL);
  fixture_endpoint_t second = {0};
  transport_config_t config = {.bind_hosts = {"127.0.0.1"},
                               .num_bind_hosts = 1,
                               .remote_hosts = {"127.0.0.1"},
                               .num_remote_hosts = 1,
                               .port = 19933,
                               .allow_insecure_peer = true,
                               .callback = fixture_event,
                               .user_data = &second};
  second.transport = transport_create(&config);
  assert(second.transport);
  for (size_t i = 0; i < 2000 && !second.authenticated; i++) {
    fixture_tick(&f);
    transport_tick(second.transport);
  }
  assert(second.authenticated && f.server.transport->conn_count == 2);
  moq_track_id_t track = {.type = MOQ_TRACK_DATA,
                          .flags = MOQ_TRACK_FLAG_FEC_ENABLED,
                          .name = "frozen-group"};
  fixture_subscribe(&f, &f.client, track);
  assert(transport_subscribe_conn(second.transport, second.conn, track));
  for (size_t i = 0; i < 2000 && f.server.subscriptions < 2; i++) {
    fixture_tick(&f);
    transport_tick(second.transport);
  }
  assert(f.server.subscriptions == 2);
  transport_t *t = f.server.transport;
  transport_conn_t *first_conn = t->conns[0], *blocked_conn = t->conns[1];
  fill_queue(blocked_conn, 64);
  uint8_t original[1000], next[1000];
  memset(original, 17, sizeof(original));
  memset(next, 23, sizeof(next));
  moq_object_t object = {
      .track_id = track, .data = original, .size = sizeof(original)};
  assert(transport_publish_ex(t, &object) == TRANSPORT_PUBLISH_BUFFERED);
  assert(!transport_publish_flush_grouped(
      t)); /* First peer accepted, second did not. */
  sent_object_cache_t *cached =
      transport_sent_cache_find(&t->sent_cache, &track, 0, 0);
  assert(cached == NULL); /* Fixed FEC never retains repair obligations. */
  assert(t->fec_buf_len == 1002 && memcmp(t->fec_buf + 2, original, 1000) == 0);
  size_t first_queued =
      quicly_get_num_datagram_frames_path(first_conn->quic, 0);
  assert(first_queued > 0);
  object.data = next;
  for (size_t i = 0; i < 3; i++) {
    assert(transport_publish_ex(t, &object) == TRANSPORT_PUBLISH_BACKPRESSURE);
    assert(t->fec_buf_len == 1002 &&
           memcmp(t->fec_buf + 2, original, 1000) == 0);
    assert(quicly_get_num_datagram_frames_path(first_conn->quic, 0) ==
           first_queued);
    assert(t->stats.recovery_cache_backpressure == 0);
  }
  for (size_t i = 0; i < 2000 && (t->fec_buf_len || f.client.objects < 1 ||
                                  second.objects < 1);
       i++) {
    fixture_tick(&f);
    transport_tick(second.transport);
  }
  assert(!t->fec_buf_len && f.client.objects == 1 && second.objects == 1);
  assert(memcmp(f.client.payload + 2, original, 1000) == 0 &&
         memcmp(second.payload + 2, original, 1000) == 0);
  assert(transport_publish_ex(t, &object) == TRANSPORT_PUBLISH_BUFFERED);
  assert(transport_publish_flush_grouped(t));
  for (size_t i = 0; i < 2000 && (f.client.objects < 2 || second.objects < 2);
       i++) {
    fixture_tick(&f);
    transport_tick(second.transport);
  }
  assert(f.client.objects == 2 && second.objects == 2 && !second.failed);
  assert(memcmp(f.client.payload + 2, next, 1000) == 0 &&
         memcmp(second.payload + 2, next, 1000) == 0);
  assert(t->stats.recovery_cache_backpressure == 0);
  /* The record triggering a partial flush is itself retained, so it must be
   * reported as BUFFERED rather than failed or rejected. */
  fill_queue(blocked_conn, 64);
  object.data = original;
  for (size_t i = 0; i < 4; i++)
    assert(transport_publish_ex(t, &object) == TRANSPORT_PUBLISH_BUFFERED);
  assert(t->fec_buf_len == 4008 && t->fec_flush_pending);
  for (size_t i = 0; i < 2000 && (t->fec_buf_len || f.client.objects < 3 ||
                                  second.objects < 3);
       i++) {
    fixture_tick(&f);
    transport_tick(second.transport);
  }
  assert(!t->fec_buf_len && f.client.objects == 3 && second.objects == 3);
  assert(f.client.payload_size == 4008 && second.payload_size == 4008);
  for (size_t i = 0; i < 4; i++) {
    assert(memcmp(f.client.payload + i * 1002 + 2, original, 1000) == 0);
    assert(memcmp(second.payload + i * 1002 + 2, original, 1000) == 0);
  }
  transport_destroy(second.transport);
  fixture_destroy(&f);
}

/* A complete group may exceed the rate's 50 ms burst, but subsequent groups
 * must repay that allocation before sending another burst. */
static void test_slow_group_admission(void) {
  const uint8_t modes[] = {MOQ_TRACK_FLAG_FEC_ENABLED,
                           MOQ_TRACK_FLAG_FEC_RATELESS};
  for (size_t mode = 0; mode < sizeof(modes); mode++) {
    transport_fixture_t f;
    fixture_create(&f, 19934, NULL, NULL);
    moq_track_id_t track = {
        .type = MOQ_TRACK_DATA, .flags = modes[mode], .name = "slow-group"};
    fixture_subscribe(&f, &f.client, track);
    transport_conn_t *conn = f.server.conn;
    conn->path_states[0].initialized = true;
    conn->path_states[0].b_ewma = FP_FROM_INT(100);
    uint8_t payload[8000] = {42};
    moq_object_t object = {
        .track_id = track, .data = payload, .size = sizeof(payload)};
    for (size_t i = 0; i < 3; i++)
      assert(transport_publish_ex(f.server.transport, &object) ==
             TRANSPORT_PUBLISH_BUFFERED);
    assert(transport_publish_ex(f.server.transport, &object) ==
           TRANSPORT_PUBLISH_DELIVERED);
    size_t queued = quicly_get_num_datagram_frames_path(conn->quic, 0);
    assert(queued >= 27 && queued <= QLINQ_PATH_DATAGRAM_QUEUE_CAPACITY);
    assert(conn->path_budgets[0].debt == FP_FROM_INT(queued));
    for (size_t i = 0; i < 4; i++)
      assert(transport_publish_ex(f.server.transport, &object) ==
             TRANSPORT_PUBLISH_BUFFERED);
    assert(f.server.transport->fec_buf_len == 32008);
    assert(!transport_publish_flush_grouped(f.server.transport));
    assert(quicly_get_num_datagram_frames_path(conn->quic, 0) == queued);
    assert(conn->admission_retry_at_ns > transport_get_monotonic_ns());
    /* Advance the budget clock without sleeping or changing the measured
     * rate. Both groups fit the actual queue once the first debt expires. */
    conn->path_budgets[0].at_ns -= UINT64_C(1000000000);
    assert(transport_publish_flush_grouped(f.server.transport));
    assert(quicly_get_num_datagram_frames_path(conn->quic, 0) == 2 * queued);
    assert(f.server.transport->fec_buf_len == 0);
    fixture_destroy(&f);
  }
}

static void test_rateless_queue_boundary(void) {
  transport_fixture_t f;
  fixture_create(&f, 19935, NULL, NULL);
  moq_track_id_t track = {.type = MOQ_TRACK_DATA,
                          .flags = MOQ_TRACK_FLAG_FEC_RATELESS,
                          .name = "rateless-boundary"};
  fixture_subscribe(&f, &f.client, track);
  assert(transport_mock_path_state(f.server.transport, 0, 100000, 1, 0));
  uint8_t payload[2000] = {42};
  moq_object_t object = {
      .track_id = track, .data = payload, .size = sizeof(payload)};
  fill_queue(f.server.conn, 62);
  assert(transport_publish_ex(f.server.transport, &object) ==
         TRANSPORT_PUBLISH_BUFFERED);
  assert(transport_publish_flush_grouped(f.server.transport));
  assert(quicly_get_num_datagram_frames_path(f.server.conn->quic, 0) == 64);
  sent_object_cache_t *cached =
      transport_sent_cache_find(&f.server.transport->sent_cache, &track, 0, 0);
  assert(cached && cached->data_symbols == 2 && cached->total_symbols == 2);
  fixture_receive(&f, &f.client, 1);
  assert(f.client.payload_size == 2002 &&
         memcmp(f.client.payload + 2, payload, sizeof(payload)) == 0);
  fixture_destroy(&f);
}

/* Small objects used to derive 16384 cache slots, exceeding the receiver's
 * 4096-object history. A missing prefix must stop new admission before the
 * sender can produce a checkpoint that the receiver cannot retain. */
static void test_recovery_history_bound(void) {
  transport_fixture_t f;
  transport_limits_t limits = {.max_fec_object_size = 1024};
  fixture_create(&f, 19936, &limits, NULL);
  moq_track_id_t track = {.type = MOQ_TRACK_DATA,
                          .flags = MOQ_TRACK_FLAG_FEC_RATELESS,
                          .name = "history-bound"};
  fixture_subscribe(&f, &f.client, track);
  transport_t *t = f.server.transport;
  assert(t->sent_cache.capacity == QLINQ_RECOVERY_HISTORY_OBJECTS);
  uint8_t payload[1000] = {42};
  moq_object_t object = {
      .track_id = track, .data = payload, .size = sizeof(payload)};
  for (size_t i = 0; i < t->sent_cache.capacity; i++) {
    object.object_id = i;
    assert(transport_sent_cache_store(&t->sent_cache, &object, 1, 1,
                                      sizeof(payload), false));
  }
  t->fec_tracks[0] =
      (transport_fec_track_state_t){.track_id = track,
                                    .active = true,
                                    .has_objects = true,
                                    .next_object_id = t->sent_cache.capacity};
  assert(!transport_publish_recovery_ready(t, &track));
  assert(transport_publish_ex(t, &object) == TRANSPORT_PUBLISH_BUFFERED);
  assert(!transport_publish_flush_grouped(t));
  assert(quicly_get_num_datagram_frames_path(f.server.conn->quic, 0) == 0);
  assert(transport_sent_cache_release_through(&t->sent_cache, &track, 0, 31) ==
         32);
  assert(transport_publish_recovery_ready(t, &track));
  assert(transport_publish_flush_grouped(t));
  assert(quicly_get_state(f.server.conn->quic) < QUICLY_STATE_CLOSING);
  fixture_destroy(&f);
}

int main(void) {
  test_queue_boundary();
  test_slow_group_admission();
  test_rateless_queue_boundary();
  test_recovery_history_bound();
  test_partial_group_retry();
  transport_fixture_t fixture;
  transport_limits_t limits = {.max_fec_object_size = 32};
  fixture_create(&fixture, 19931, NULL, &limits);
  moq_track_id_t track = {.type = MOQ_TRACK_DATA,
                          .flags = MOQ_TRACK_FLAG_FEC_RATELESS,
                          .name = "small"};
  fixture_subscribe(&fixture, &fixture.client, track);
  uint8_t payload[33];
  memset(payload, 17, sizeof(payload));
  moq_object_t object = {.track_id = track, .data = payload, .size = 31};
  assert(transport_publish_ex(fixture.server.transport, &object) ==
         TRANSPORT_PUBLISH_INVALID);
  assert(fixture.server.transport->fec_buf_len == 0);
  object.size = 10;
  /* Three framed records cannot share one 32-byte object: flush the first
   * two before admitting the third, preserving every record exactly once. */
  for (size_t i = 0; i < 3; i++)
    assert(transport_publish(fixture.server.transport, &object));
  fixture_receive(&fixture, &fixture.client, 2);
  assert(fixture.client.payload_size == 12);
  sent_object_cache_t *cached = transport_sent_cache_find(
      &fixture.server.transport->sent_cache, &track, 0, 0);
  assert(cached && cached->symbol_size == 24 && cached->data_symbols == 1);
  assert(memcmp(fixture.client.payload + 2, payload, 10) == 0);
  track.type = MOQ_TRACK_VIDEO;
  track.flags = 0;
  fixture_subscribe(&fixture, &fixture.client, track);
  object.track_id = track;
  object.size = 33;
  assert(transport_publish_ex(fixture.server.transport, &object) ==
         TRANSPORT_PUBLISH_INVALID);
  const uint8_t flags[] = {0, MOQ_TRACK_FLAG_FEC_ENABLED,
                           MOQ_TRACK_FLAG_FEC_RATELESS};
  for (size_t i = 0; i < sizeof(flags); i++) {
    track.flags = flags[i];
    snprintf(track.name, sizeof(track.name), "mode-%zu", i);
    fixture_subscribe(&fixture, &fixture.client, track);
    object.track_id = track;
    object.size = 17;
    size_t expected = fixture.client.objects + 1;
    assert(transport_publish(fixture.server.transport, &object));
    fixture_receive(&fixture, &fixture.client, expected);
    assert(fixture.client.last_track.flags == track.flags);
    assert(strcmp(fixture.client.last_track.name, track.name) == 0);
    assert(fixture.client.payload_size == 17 &&
           memcmp(fixture.client.payload, payload, 17) == 0);
  }
  fixture_destroy(&fixture);
  puts("===PUBLICATION LIMITS OK===");
  return 0;
}
