#include "transport_wire.h"

#include <stdio.h>
#include <string.h>

#define CHECK(condition, message)                                              \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "wire test failed: %s\n", message);                      \
      return 1;                                                                \
    }                                                                          \
  } while (0)

int main(void) {
  uint8_t payload[4096];
  uint8_t frame_buf[8192];
  size_t payload_len = 0;
  size_t frame_len = 0;

  qlinq_wire_track_t track = {
      .alias = 9, .track_type = 4, .flags = 6, .name = "telemetry/input"};
  CHECK(qlinq_wire_encode_track(payload, sizeof(payload), &track,
                                &payload_len) == QLINQ_WIRE_OK,
        "track encode");
  CHECK(qlinq_wire_encode_frame(frame_buf, sizeof(frame_buf),
                                QLINQ_WIRE_SUBSCRIBE, payload, payload_len,
                                sizeof(payload), &frame_len) == QLINQ_WIRE_OK,
        "frame encode");

  qlinq_wire_frame_t frame;
  CHECK(qlinq_wire_decode_frame(frame_buf, QLINQ_WIRE_FRAME_HEADER_SIZE - 1,
                                sizeof(payload),
                                &frame) == QLINQ_WIRE_NEED_MORE,
        "partial header");
  CHECK(qlinq_wire_decode_frame(frame_buf, frame_len - 1, sizeof(payload),
                                &frame) == QLINQ_WIRE_NEED_MORE,
        "partial payload");
  CHECK(qlinq_wire_decode_frame(frame_buf, frame_len, sizeof(payload),
                                &frame) == QLINQ_WIRE_OK,
        "frame decode");
  CHECK(frame.type == QLINQ_WIRE_SUBSCRIBE && frame.consumed == frame_len,
        "frame metadata");

  qlinq_wire_track_t decoded_track;
  CHECK(qlinq_wire_decode_track(frame.payload, frame.payload_len,
                                &decoded_track) == QLINQ_WIRE_OK,
        "track decode");
  CHECK(decoded_track.alias == track.alias &&
            decoded_track.track_type == track.track_type &&
            decoded_track.flags == track.flags &&
            strcmp(decoded_track.name, track.name) == 0,
        "track roundtrip");

  uint8_t corrupted[8192];
  memcpy(corrupted, frame_buf, frame_len);
  corrupted[2] = QLINQ_WIRE_VERSION + 1;
  CHECK(qlinq_wire_decode_frame(corrupted, frame_len, sizeof(payload),
                                &frame) == QLINQ_WIRE_UNSUPPORTED_VERSION,
        "version rejection");
  memcpy(corrupted, frame_buf, frame_len);
  corrupted[0] ^= 0xff;
  CHECK(qlinq_wire_decode_frame(corrupted, frame_len, sizeof(payload),
                                &frame) == QLINQ_WIRE_INVALID,
        "magic rejection");
  memcpy(corrupted, frame_buf, frame_len);
  corrupted[3] = 0xff;
  CHECK(qlinq_wire_decode_frame(corrupted, frame_len, sizeof(payload),
                                &frame) == QLINQ_WIRE_INVALID,
        "unknown type rejection");
  corrupted[3] = 15;
  CHECK(qlinq_wire_decode_frame(corrupted, frame_len, sizeof(payload),
                                &frame) == QLINQ_WIRE_INVALID,
        "removed private Flexicast controls rejected");
  CHECK(qlinq_wire_decode_frame(frame_buf, frame_len, payload_len - 1,
                                &frame) == QLINQ_WIRE_TOO_LARGE,
        "configured size limit");
  CHECK(qlinq_wire_encode_frame_header(frame_buf, QLINQ_WIRE_FRAME_HEADER_SIZE,
                                       QLINQ_WIRE_TRACK_OBJECT, 17,
                                       16) == QLINQ_WIRE_TOO_LARGE,
        "frame header size limit");

  uint8_t malformed_track[] = {9, 4, 0, 2, 'x'};
  CHECK(qlinq_wire_decode_track(malformed_track, sizeof(malformed_track),
                                &decoded_track) == QLINQ_WIRE_INVALID,
        "track length mismatch");

  const uint16_t missing[] = {1, 7, 1023};
  const uint64_t large_group_id = UINT64_C(0x12345678abcdef01);
  const uint64_t large_object_id = UINT64_C(0xfedcba9876543210);
  CHECK(qlinq_wire_encode_nack(payload, sizeof(payload), 13, 0, large_group_id,
                               large_object_id, missing, 3,
                               &payload_len) == QLINQ_WIRE_OK,
        "nack encode");
  qlinq_wire_nack_t nack;
  CHECK(qlinq_wire_decode_nack(payload, payload_len, &nack) == QLINQ_WIRE_OK,
        "nack decode");
  CHECK(nack.alias == 13 && nack.flags == 0 &&
            nack.group_id == large_group_id &&
            nack.object_id == large_object_id && nack.missing_count == 3,
        "nack metadata");
  for (size_t i = 0; i < 3; i++) {
    uint16_t index = 0;
    CHECK(qlinq_wire_nack_index(&nack, i, &index) && index == missing[i],
          "nack index roundtrip");
  }
  payload[1] = 4;
  CHECK(qlinq_wire_decode_nack(payload, payload_len, &nack) ==
            QLINQ_WIRE_INVALID,
        "nack reserved byte");
  payload[1] = 0;
  payload[19] = 4;
  CHECK(qlinq_wire_decode_nack(payload, payload_len, &nack) ==
            QLINQ_WIRE_INVALID,
        "nack count mismatch");
  CHECK(qlinq_wire_encode_nack(payload, sizeof(payload), 13,
                               QLINQ_WIRE_NACK_WHOLE_OBJECT, large_group_id,
                               large_object_id, NULL, 0,
                               &payload_len) == QLINQ_WIRE_OK &&
            qlinq_wire_decode_nack(payload, payload_len, &nack) ==
                QLINQ_WIRE_OK &&
            nack.flags == QLINQ_WIRE_NACK_WHOLE_OBJECT &&
            nack.missing_count == 0,
        "whole-object nack roundtrip");
  CHECK(qlinq_wire_encode_nack(payload, sizeof(payload), 13,
                               QLINQ_WIRE_NACK_RATELESS, large_group_id,
                               large_object_id, NULL, 7,
                               &payload_len) == QLINQ_WIRE_OK &&
            payload_len == 20 &&
            qlinq_wire_decode_nack(payload, payload_len, &nack) ==
                QLINQ_WIRE_OK &&
            nack.flags == QLINQ_WIRE_NACK_RATELESS && nack.missing_count == 7 &&
            nack.encoded_indices == NULL,
        "rateless nack uses constant-size deficit encoding");
  uint16_t unused_index = 0;
  CHECK(!qlinq_wire_nack_index(&nack, 0, &unused_index) &&
            qlinq_wire_encode_nack(payload, sizeof(payload), 13,
                                   QLINQ_WIRE_NACK_RATELESS, large_group_id,
                                   large_object_id, missing, 1,
                                   &payload_len) == QLINQ_WIRE_INVALID &&
            qlinq_wire_encode_nack(payload, sizeof(payload), 13,
                                   QLINQ_WIRE_NACK_RATELESS, large_group_id,
                                   large_object_id, NULL, 0,
                                   &payload_len) == QLINQ_WIRE_INVALID,
        "rateless nack rejects indices and empty partial deficit");
  CHECK(qlinq_wire_encode_nack(payload, sizeof(payload), 13,
                               QLINQ_WIRE_NACK_RATELESS |
                                   QLINQ_WIRE_NACK_WHOLE_OBJECT,
                               large_group_id, large_object_id, NULL, 0,
                               &payload_len) == QLINQ_WIRE_OK &&
            payload_len == 20 &&
            qlinq_wire_decode_nack(payload, payload_len, &nack) ==
                QLINQ_WIRE_OK,
        "rateless whole-object request is constant-sized");

  qlinq_wire_track_object_t track_object = {.alias = 17,
                                            .is_keyframe = true,
                                            .priority = 2,
                                            .group_id = large_group_id,
                                            .object_id = large_object_id};
  const uint8_t object_bytes[] = {4, 3, 2, 1};
  CHECK(qlinq_wire_encode_track_object(payload, sizeof(payload),
                                       &track_object) == QLINQ_WIRE_OK,
        "track object encode");
  memcpy(payload + QLINQ_WIRE_TRACK_OBJECT_HEADER_SIZE, object_bytes,
         sizeof(object_bytes));
  qlinq_wire_track_object_t decoded_object;
  const uint8_t *decoded_payload = NULL;
  size_t decoded_payload_len = 0;
  CHECK(qlinq_wire_decode_track_object(
            payload, QLINQ_WIRE_TRACK_OBJECT_HEADER_SIZE + sizeof(object_bytes),
            &decoded_object, &decoded_payload,
            &decoded_payload_len) == QLINQ_WIRE_OK,
        "track object decode");
  CHECK(decoded_object.alias == track_object.alias &&
            decoded_object.is_keyframe == track_object.is_keyframe &&
            decoded_object.priority == track_object.priority &&
            decoded_object.group_id == large_group_id &&
            decoded_object.object_id == large_object_id &&
            decoded_payload_len == sizeof(object_bytes) &&
            memcmp(decoded_payload, object_bytes, sizeof(object_bytes)) == 0,
        "track object roundtrip");
  payload[3] = 1;
  CHECK(qlinq_wire_decode_track_object(
            payload, QLINQ_WIRE_TRACK_OBJECT_HEADER_SIZE, &decoded_object,
            &decoded_payload, &decoded_payload_len) == QLINQ_WIRE_INVALID,
        "track object reserved byte");

  qlinq_wire_fec_header_t fec = {.alias = 12,
                                 .is_keyframe = true,
                                 .priority = 2,
                                 .path_id = 3,
                                 .group_id = large_group_id,
                                 .object_id = large_object_id,
                                 .symbol_index = 7,
                                 .total_symbols = 20,
                                 .data_symbols = 16,
                                 .symbol_size = 1200,
                                 .original_size = 19000,
                                 .send_time_ns = UINT64_C(1234567890123)};
  CHECK(qlinq_wire_encode_fec_header(payload, sizeof(payload), &fec) ==
            QLINQ_WIRE_OK,
        "FEC encode");
  qlinq_wire_fec_header_t decoded_fec;
  CHECK(qlinq_wire_decode_fec_header(payload, QLINQ_WIRE_FEC_HEADER_SIZE,
                                     &decoded_fec) == QLINQ_WIRE_OK,
        "FEC decode");
  uint8_t datagram_type = 0;
  CHECK(qlinq_wire_decode_datagram_type(payload, QLINQ_WIRE_FEC_HEADER_SIZE,
                                        &datagram_type) == QLINQ_WIRE_OK &&
            datagram_type == QLINQ_WIRE_DATAGRAM_FEC,
        "FEC datagram type");
  CHECK(decoded_fec.alias == fec.alias &&
            decoded_fec.is_keyframe == fec.is_keyframe &&
            decoded_fec.priority == fec.priority &&
            decoded_fec.path_id == fec.path_id &&
            decoded_fec.group_id == fec.group_id &&
            decoded_fec.object_id == fec.object_id &&
            decoded_fec.symbol_index == fec.symbol_index &&
            decoded_fec.total_symbols == fec.total_symbols &&
            decoded_fec.data_symbols == fec.data_symbols &&
            decoded_fec.symbol_size == fec.symbol_size &&
            decoded_fec.original_size == fec.original_size &&
            decoded_fec.send_time_ns == fec.send_time_ns,
        "FEC roundtrip");
  payload[5] = 2;
  CHECK(qlinq_wire_decode_fec_header(payload, QLINQ_WIRE_FEC_HEADER_SIZE,
                                     &decoded_fec) == QLINQ_WIRE_INVALID,
        "FEC keyframe validation");

  qlinq_wire_telemetry_t telemetry = {.path_id = 2,
                                      .send_time_ns = UINT64_C(987654321),
                                      .recv_time_ns = UINT64_C(987655555)};
  CHECK(qlinq_wire_encode_telemetry(payload, sizeof(payload), &telemetry) ==
            QLINQ_WIRE_OK,
        "telemetry encode");
  qlinq_wire_telemetry_t decoded_telemetry;
  CHECK(qlinq_wire_decode_telemetry(payload, QLINQ_WIRE_TELEMETRY_SIZE,
                                    &decoded_telemetry) == QLINQ_WIRE_OK,
        "telemetry decode");
  CHECK(qlinq_wire_decode_datagram_type(payload, QLINQ_WIRE_TELEMETRY_SIZE,
                                        &datagram_type) == QLINQ_WIRE_OK &&
            datagram_type == QLINQ_WIRE_DATAGRAM_TELEMETRY,
        "telemetry datagram type");
  CHECK(decoded_telemetry.path_id == telemetry.path_id &&
            decoded_telemetry.send_time_ns == telemetry.send_time_ns &&
            decoded_telemetry.recv_time_ns == telemetry.recv_time_ns,
        "telemetry roundtrip");
  CHECK(qlinq_wire_decode_telemetry(payload, QLINQ_WIRE_TELEMETRY_SIZE + 1,
                                    &decoded_telemetry) == QLINQ_WIRE_INVALID,
        "telemetry trailing bytes");
  payload[3] = 0xff;
  CHECK(qlinq_wire_decode_datagram_type(payload, QLINQ_WIRE_TELEMETRY_SIZE,
                                        &datagram_type) == QLINQ_WIRE_INVALID,
        "unknown datagram type");
  CHECK(qlinq_wire_decode_datagram_type(payload, 3, &datagram_type) ==
            QLINQ_WIRE_NEED_MORE,
        "partial datagram envelope");

  qlinq_wire_hello_t hello = {.role = QLINQ_WIRE_ROLE_CLIENT,
                              .max_paths = 4,
                              .capabilities = QLINQ_WIRE_CAP_RELIABLE |
                                              QLINQ_WIRE_CAP_DATAGRAM |
                                              QLINQ_WIRE_CAP_FEC_RATELESS |
                                              QLINQ_WIRE_CAP_RATELESS_REPAIR,
                              .max_reliable_object_size = 1024U * 1024U - 16U,
                              .max_fec_object_size = 1024U * 1024U,
                              .max_subscriptions = 32,
                              .max_datagram_size = 1500};
  CHECK(qlinq_wire_encode_hello(payload, sizeof(payload), &hello) ==
            QLINQ_WIRE_OK,
        "hello encode");
  qlinq_wire_hello_t decoded_hello;
  CHECK(qlinq_wire_decode_hello(payload, QLINQ_WIRE_HELLO_SIZE,
                                &decoded_hello) == QLINQ_WIRE_OK,
        "hello decode");
  CHECK(decoded_hello.role == hello.role &&
            decoded_hello.max_paths == hello.max_paths &&
            decoded_hello.capabilities == hello.capabilities &&
            decoded_hello.max_reliable_object_size ==
                hello.max_reliable_object_size &&
            decoded_hello.max_fec_object_size == hello.max_fec_object_size &&
            decoded_hello.max_subscriptions == hello.max_subscriptions &&
            decoded_hello.max_datagram_size == hello.max_datagram_size,
        "hello roundtrip");
  CHECK(qlinq_wire_encode_frame(frame_buf, sizeof(frame_buf), QLINQ_WIRE_HELLO,
                                payload, QLINQ_WIRE_HELLO_SIZE, sizeof(payload),
                                &frame_len) == QLINQ_WIRE_OK &&
            qlinq_wire_decode_frame(frame_buf, frame_len, sizeof(payload),
                                    &frame) == QLINQ_WIRE_OK &&
            frame.type == QLINQ_WIRE_HELLO,
        "hello frame");
  payload[1] = 1;
  CHECK(qlinq_wire_decode_hello(payload, QLINQ_WIRE_HELLO_SIZE,
                                &decoded_hello) == QLINQ_WIRE_INVALID,
        "hello reserved byte");
  payload[1] = 0;
  payload[0] = 2;
  CHECK(qlinq_wire_decode_hello(payload, QLINQ_WIRE_HELLO_SIZE,
                                &decoded_hello) == QLINQ_WIRE_INVALID,
        "hello role validation");

  qlinq_wire_flexicast_bind_t bind = {
      .alias = 17, .flow_id = UINT64_C(0x8877665544332211), .key_epoch = 3};
  CHECK(qlinq_wire_encode_flexicast_bind(payload, sizeof(payload), &bind) ==
            QLINQ_WIRE_OK,
        "flexicast binding encode");
  CHECK(qlinq_wire_encode_flexicast_bind(payload,
                                         QLINQ_WIRE_FLEXICAST_BIND_SIZE - 1,
                                         &bind) == QLINQ_WIRE_TOO_LARGE,
        "flexicast binding capacity");
  qlinq_wire_flexicast_bind_t decoded_bind;
  CHECK(qlinq_wire_decode_flexicast_bind(payload,
                                         QLINQ_WIRE_FLEXICAST_BIND_SIZE,
                                         &decoded_bind) == QLINQ_WIRE_OK &&
            decoded_bind.alias == bind.alias &&
            decoded_bind.flow_id == bind.flow_id &&
            decoded_bind.key_epoch == bind.key_epoch,
        "flexicast binding roundtrip");
  payload[1] = 1;
  CHECK(qlinq_wire_decode_flexicast_bind(payload,
                                         QLINQ_WIRE_FLEXICAST_BIND_SIZE,
                                         &decoded_bind) == QLINQ_WIRE_INVALID,
        "flexicast binding reserved byte");

  CHECK(qlinq_wire_encode_frame(frame_buf, sizeof(frame_buf),
                                QLINQ_WIRE_FLEXICAST_BIND, payload,
                                QLINQ_WIRE_FLEXICAST_BIND_SIZE, sizeof(payload),
                                &frame_len) == QLINQ_WIRE_OK,
        "flexicast control frame recognized");

  qlinq_wire_track_end_t track_end = {
      .alias = 21,
      .group_id = large_group_id,
      .final_object_id = large_object_id,
  };
  CHECK(qlinq_wire_encode_track_end(payload, sizeof(payload), &track_end) ==
            QLINQ_WIRE_OK,
        "track completion encode");
  CHECK(qlinq_wire_encode_track_end(payload, QLINQ_WIRE_TRACK_END_SIZE - 1,
                                    &track_end) == QLINQ_WIRE_TOO_LARGE,
        "track completion capacity");
  qlinq_wire_track_end_t decoded_end;
  CHECK(qlinq_wire_decode_track_end(payload, QLINQ_WIRE_TRACK_END_SIZE,
                                    &decoded_end) == QLINQ_WIRE_OK &&
            decoded_end.alias == track_end.alias &&
            decoded_end.group_id == track_end.group_id &&
            decoded_end.final_object_id == track_end.final_object_id,
        "track completion roundtrip");
  CHECK(qlinq_wire_decode_track_end(payload, QLINQ_WIRE_TRACK_END_SIZE - 1,
                                    &decoded_end) == QLINQ_WIRE_INVALID,
        "track completion length");
  CHECK(qlinq_wire_encode_frame(frame_buf, sizeof(frame_buf),
                                QLINQ_WIRE_TRACK_END, payload,
                                QLINQ_WIRE_TRACK_END_SIZE, sizeof(payload),
                                &frame_len) == QLINQ_WIRE_OK,
        "track completion control frame recognized");

  qlinq_wire_track_abort_t track_abort = {.alias = 23};
  CHECK(qlinq_wire_encode_track_abort(payload, sizeof(payload), &track_abort) ==
            QLINQ_WIRE_OK,
        "track abort encode");
  qlinq_wire_track_abort_t decoded_abort;
  CHECK(qlinq_wire_decode_track_abort(payload, QLINQ_WIRE_TRACK_ABORT_SIZE,
                                      &decoded_abort) == QLINQ_WIRE_OK &&
            decoded_abort.alias == track_abort.alias,
        "track abort roundtrip");
  payload[1] = 1;
  CHECK(qlinq_wire_decode_track_abort(payload, QLINQ_WIRE_TRACK_ABORT_SIZE,
                                      &decoded_abort) == QLINQ_WIRE_INVALID,
        "track abort reserved bytes");
  payload[1] = 0;
  CHECK(qlinq_wire_encode_frame(frame_buf, sizeof(frame_buf),
                                QLINQ_WIRE_TRACK_ABORT, payload,
                                QLINQ_WIRE_TRACK_ABORT_SIZE, sizeof(payload),
                                &frame_len) == QLINQ_WIRE_OK,
        "track abort control frame recognized");

  qlinq_wire_track_checkpoint_t checkpoint = {
      .alias = 22,
      .flags = 0,
      .group_id = large_group_id,
      .first_object_id = 64,
      .final_object_id = 95,
  };
  CHECK(qlinq_wire_encode_track_checkpoint(payload, sizeof(payload),
                                           &checkpoint) == QLINQ_WIRE_OK,
        "recovery checkpoint encode");
  CHECK(qlinq_wire_encode_track_checkpoint(payload,
                                           QLINQ_WIRE_TRACK_CHECKPOINT_SIZE - 1,
                                           &checkpoint) == QLINQ_WIRE_TOO_LARGE,
        "recovery checkpoint capacity");
  qlinq_wire_track_checkpoint_t decoded_checkpoint;
  CHECK(qlinq_wire_decode_track_checkpoint(
            payload, QLINQ_WIRE_TRACK_CHECKPOINT_SIZE, &decoded_checkpoint) ==
                QLINQ_WIRE_OK &&
            decoded_checkpoint.alias == checkpoint.alias &&
            decoded_checkpoint.flags == checkpoint.flags &&
            decoded_checkpoint.group_id == checkpoint.group_id &&
            decoded_checkpoint.first_object_id == checkpoint.first_object_id &&
            decoded_checkpoint.final_object_id == checkpoint.final_object_id,
        "recovery checkpoint roundtrip");
  checkpoint.first_object_id = 96;
  CHECK(qlinq_wire_encode_track_checkpoint(payload, sizeof(payload),
                                           &checkpoint) == QLINQ_WIRE_INVALID,
        "recovery checkpoint range validation");
  checkpoint.first_object_id = checkpoint.final_object_id;
  checkpoint.flags = 0x80;
  CHECK(qlinq_wire_encode_track_checkpoint(payload, sizeof(payload),
                                           &checkpoint) == QLINQ_WIRE_INVALID,
        "recovery checkpoint flag validation");

  qlinq_wire_track_checkpoint_ack_t checkpoint_ack = {
      .alias = 22,
      .group_id = large_group_id,
      .final_object_id = 95,
  };
  CHECK(qlinq_wire_encode_track_checkpoint_ack(
            payload, sizeof(payload), &checkpoint_ack) == QLINQ_WIRE_OK,
        "recovery checkpoint ACK encode");
  qlinq_wire_track_checkpoint_ack_t decoded_checkpoint_ack;
  CHECK(qlinq_wire_decode_track_checkpoint_ack(
            payload, QLINQ_WIRE_TRACK_CHECKPOINT_ACK_SIZE,
            &decoded_checkpoint_ack) == QLINQ_WIRE_OK &&
            decoded_checkpoint_ack.alias == checkpoint_ack.alias &&
            decoded_checkpoint_ack.group_id == checkpoint_ack.group_id &&
            decoded_checkpoint_ack.final_object_id ==
                checkpoint_ack.final_object_id,
        "recovery checkpoint ACK roundtrip");
  CHECK(qlinq_wire_encode_frame(frame_buf, sizeof(frame_buf),
                                QLINQ_WIRE_TRACK_CHECKPOINT_ACK, payload,
                                QLINQ_WIRE_TRACK_CHECKPOINT_ACK_SIZE,
                                sizeof(payload), &frame_len) == QLINQ_WIRE_OK,
        "recovery checkpoint ACK frame recognized");

  printf("===TRANSPORT WIRE OK===\n");
  return 0;
}
