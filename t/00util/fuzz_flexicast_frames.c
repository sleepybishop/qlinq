#include <quicly/flexicast.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0 || size > 4096)
    return 0;
  uint64_t type = data[0] % 3U == 0   ? QUICLY_FRAME_TYPE_FC_ANNOUNCE
                  : data[0] % 3U == 1 ? QUICLY_FRAME_TYPE_FC_STATE
                                      : QUICLY_FRAME_TYPE_FC_KEY;
  uint8_t framed[4104];
  uint8_t *end = quicly_encodev(framed, type);
  memcpy(end, data + 1, size - 1U);
  size_t framed_size = (size_t)(end - framed) + size - 1U;
  size_t consumed = 0;
  quicly_flexicast_announce_frame_t announce;
  (void)quicly_flexicast_decode_announce_frame(framed, framed_size, &announce,
                                               &consumed);

  consumed = 0;
  quicly_flexicast_state_frame_t state;
  (void)quicly_flexicast_decode_state_frame(framed, framed_size, &state,
                                            &consumed);

  consumed = 0;
  quicly_flexicast_key_frame_t key;
  (void)quicly_flexicast_decode_key_frame(framed, framed_size, &key, &consumed);
  return 0;
}
