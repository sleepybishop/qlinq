#include "transport_fixture.h"
#include <stdio.h>

int main(void) {
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
