#include "transport_fixture.h"
#include <stdio.h>

static void run_mode(uint8_t flags) {
  transport_fixture_t fixture;
  transport_limits_t limits = {.max_subscriptions_per_connection = 2};
  fixture_create(&fixture, 19932, &limits, &limits);
  moq_track_id_t tracks[2] = {
      {.type = MOQ_TRACK_DATA, .flags = flags, .name = "alpha"},
      {.type = MOQ_TRACK_DATA, .flags = flags, .name = "beta"}};
  /* Alias 8 names alpha in one direction and beta in the other. */
  fixture_subscribe(&fixture, &fixture.client, tracks[0]);
  fixture_subscribe(&fixture, &fixture.client, tracks[1]);
  fixture_subscribe(&fixture, &fixture.server, tracks[1]);
  fixture_subscribe(&fixture, &fixture.server, tracks[0]);
  for (size_t round = 0; round < 3; round++) {
    for (size_t side = 0; side < 2; side++) {
      fixture_endpoint_t *source = side ? &fixture.client : &fixture.server;
      fixture_endpoint_t *receiver = side ? &fixture.server : &fixture.client;
      for (size_t track = 0; track < 2; track++) {
        uint8_t payload = (uint8_t)(10 * side + 2 * round + track);
        moq_object_t object = {.track_id = tracks[track],
                               .data = &payload,
                               .size = 1,
                               .object_id = round};
        size_t expected = receiver->objects + 1;
        assert(transport_publish(source->transport, &object));
        fixture_receive(&fixture, receiver, expected);
        assert(strcmp(receiver->last_track.name, tracks[track].name) == 0);
        assert(receiver->last_track.flags == flags);
        size_t prefix =
            flags & (MOQ_TRACK_FLAG_FEC_ENABLED | MOQ_TRACK_FLAG_FEC_RATELESS)
                ? 2
                : 0;
        assert(receiver->payload_size == prefix + 1 &&
               receiver->payload[prefix] == payload);
      }
    }
  }
  assert(transport_unsubscribe(fixture.client.transport, tracks[0]));
  for (size_t i = 0; i < 30; i++)
    fixture_tick(&fixture);
  /* Removing a receive mapping must leave the reverse publisher intact. */
  uint8_t payload = 99;
  moq_object_t object = {
      .track_id = tracks[0], .data = &payload, .size = 1, .object_id = 99};
  size_t expected = fixture.server.objects + 1;
  assert(transport_publish(fixture.client.transport, &object));
  fixture_receive(&fixture, &fixture.server, expected);
  assert(strcmp(fixture.server.last_track.name, "alpha") == 0);
  fixture_subscribe(&fixture, &fixture.client, tracks[0]);
  fixture_destroy(&fixture);
}

int main(void) {
  run_mode(MOQ_TRACK_FLAG_RELIABLE);
  run_mode(0);
  run_mode(MOQ_TRACK_FLAG_FEC_ENABLED);
  run_mode(MOQ_TRACK_FLAG_FEC_RATELESS);
  puts("===DIRECTIONAL SUBSCRIPTIONS OK===");
  return 0;
}
