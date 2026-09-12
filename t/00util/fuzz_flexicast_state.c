#include "picotls/openssl.h"
#include "quicly/defaults.h"
#include "quicly/flexicast.h"
#include "transport_fec_state.h"
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* Stateful model, independent of sockets: membership churn, duplicate and
 * delayed feedback, erasure/replay, epoch rotation, and protected repair-cache
 * admission/release. The frame-codec fuzzer separately mutates wire encodings.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2 || size > 1024)
    return 0;
  uint8_t secret[32] = {0};
  quicly_flexicast_config_t config = {
      .flow_id = 12345,
      .cipher_suite = &ptls_openssl_aes128gcmsha256,
      .crypto_engine = &quicly_default_crypto_engine,
      .traffic_secret = ptls_iovec_init(secret, sizeof(secret)),
      .max_members = 8};
  quicly_flexicast_flow_t *source = NULL, *receiver = NULL;
  assert(quicly_flexicast_flow_create(&source, &config) == QUICLY_FLEXICAST_OK);
  assert(quicly_flexicast_flow_create(&receiver, &config) ==
         QUICLY_FLEXICAST_OK);
  uint8_t active = 0, pending[512] = {0};
  uint64_t first = 0, next = 0;
  transport_sent_cache_t cache = {0};
  uint8_t payload[64];
  bool cached[512] = {0};
  size_t cache_count = 0;
  moq_track_id_t track = {.type = MOQ_TRACK_DATA,
                          .flags = MOQ_TRACK_FLAG_FEC_ENABLED,
                          .name = "fuzz"};
  for (size_t offset = 0; offset + 1 < size; offset += 2) {
    uint8_t action = data[offset] % 8;
    unsigned member = data[offset + 1] % 8;
    uint8_t bit = (uint8_t)(1U << member);
    int complete;
    int64_t now = 100 + (int64_t)offset;
    if (action == 0) {
      assert(quicly_flexicast_attach_at(source, member + 1, now) ==
             QUICLY_FLEXICAST_OK);
      active |= bit;
    } else if (action == 1) {
      (void)quicly_flexicast_detach_at(source, member + 1, now);
      active &= (uint8_t)~bit;
      for (uint64_t pn = first; pn < next; pn++)
        pending[pn] &= (uint8_t)~bit;
    } else if (action == 2 && active != 0) {
      memset(payload, data[offset + 1], sizeof(payload));
      uint8_t packet[128], duplicate[128];
      size_t packet_size;
      uint64_t pn;
      assert(quicly_flexicast_send_datagram_at(
                 source, ptls_iovec_init(payload, sizeof(payload)), packet,
                 sizeof(packet), &packet_size, &pn,
                 now) == QUICLY_FLEXICAST_OK);
      assert(pn == next && pn < 512);
      pending[next++] = active;
      assert(packet_size ==
             quicly_flexicast_datagram_size(source, sizeof(payload)));
      if ((data[offset + 1] & 0x80) == 0) {
        memcpy(duplicate, packet, packet_size);
        ptls_iovec_t decoded;
        uint64_t received;
        assert(quicly_flexicast_receive_datagram_at(
                   receiver, packet, packet_size, &decoded, &received,
                   now + 5) == QUICLY_FLEXICAST_OK);
        assert(received == pn && decoded.len == sizeof(payload));
        assert(memcmp(decoded.base, payload, sizeof(payload)) == 0);
        assert(quicly_flexicast_receive_datagram_at(
                   receiver, duplicate, packet_size, &decoded, &received,
                   now + 6) != QUICLY_FLEXICAST_OK);
      }
      moq_object_t object = {.track_id = track,
                             .object_id = pn,
                             .data = payload,
                             .size = sizeof(payload)};
      bool accepted = transport_sent_cache_store(&cache, &object, 1, 1,
                                                 sizeof(payload), false);
      assert(accepted == (cache_count < TRANSPORT_SENT_CACHE_SIZE));
      if (accepted) {
        cached[pn] = true;
        cache_count++;
      }
    } else if ((action == 3 || action == 4) && next != 0) {
      uint64_t pn = data[offset + 1] % next;
      if (action == 3)
        (void)quicly_flexicast_ack_at(source, member + 1, pn, &complete, now);
      else
        (void)quicly_flexicast_abandon_datagram(source, member + 1, pn,
                                                &complete);
      if (active & bit)
        pending[pn] &= (uint8_t)~bit;
    } else if (action == 5) {
      secret[offset % sizeof(secret)]++;
      assert(quicly_flexicast_flow_rekey(
                 source, ptls_iovec_init(secret, sizeof(secret)), next, now) ==
             QUICLY_FLEXICAST_OK);
      assert(quicly_flexicast_flow_rekey(
                 receiver, ptls_iovec_init(secret, sizeof(secret)), next,
                 now) == QUICLY_FLEXICAST_OK);
      active = 0;
      first = next;
    } else if (action == 6 && next != 0) {
      uint64_t watermark = data[offset + 1] % next;
      size_t released = 0;
      for (uint64_t pn = 0; pn <= watermark; pn++) {
        released += cached[pn];
        cached[pn] = false;
      }
      assert(transport_sent_cache_release_through(&cache, &track, 0,
                                                  watermark) == released);
      cache_count -= released;
    }
    assert(quicly_flexicast_num_members(source) ==
           (size_t)__builtin_popcount(active));
    for (uint64_t pn = first; pn < next; pn++) {
      size_t remaining = 0;
      int result = quicly_flexicast_get_pending_members(source, pn, &remaining);
      if (pending[pn] != 0) {
        assert(result == QUICLY_FLEXICAST_OK);
        assert(remaining == (size_t)__builtin_popcount(pending[pn]));
      } else {
        assert(result != QUICLY_FLEXICAST_OK || remaining == 0);
      }
    }
    assert(transport_sent_cache_has_space(&cache) ==
           (cache_count < TRANSPORT_SENT_CACHE_SIZE));
  }
  transport_sent_cache_destroy(&cache);
  quicly_flexicast_flow_free(source);
  quicly_flexicast_flow_free(receiver);
  return 0;
}
