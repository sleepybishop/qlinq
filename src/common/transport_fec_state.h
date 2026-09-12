#ifndef QLINQ_TRANSPORT_FEC_STATE_H
#define QLINQ_TRANSPORT_FEC_STATE_H

#include "fec.h"
#include "transport.h"

#include <stddef.h>
#include <stdint.h>

#define QLINQ_FEC_MAX_TOTAL_SYMBOLS 1024U
#define QLINQ_FEC_MAX_SYMBOL_SIZE 1500U
#define TRANSPORT_SENT_CACHE_SIZE 256U
#define TRANSPORT_FEC_CACHE_SIZE 8U

typedef struct {
  moq_track_id_t track_id;
  uint64_t group_id;
  uint64_t object_id;
  uint8_t *data;
  size_t size;
  uint8_t priority;
  bool is_keyframe;
  uint16_t total_symbols;
  uint16_t data_symbols;
  uint16_t symbol_size;
  uint16_t next_repair_symbol;
  uint16_t next_systematic_repair_symbol;
  /* Retain unconfirmed recovery obligations until explicit release. */
  bool recovery_protected;
} sent_object_cache_t;

typedef struct {
  sent_object_cache_t entries[TRANSPORT_SENT_CACHE_SIZE];
  size_t next_entry;
} transport_sent_cache_t;

sent_object_cache_t *transport_sent_cache_find(transport_sent_cache_t *cache,
                                               const moq_track_id_t *track,
                                               uint64_t group_id,
                                               uint64_t object_id);
bool transport_sent_cache_has_space(const transport_sent_cache_t *cache);
bool transport_sent_cache_store(transport_sent_cache_t *cache,
                                const moq_object_t *object,
                                uint16_t total_symbols, uint16_t data_symbols,
                                uint16_t symbol_size, bool allow_evict);
size_t transport_sent_cache_release_through(transport_sent_cache_t *cache,
                                            const moq_track_id_t *track,
                                            uint64_t group_id,
                                            uint64_t object_id);
size_t transport_sent_cache_release_track(transport_sent_cache_t *cache,
                                          const moq_track_id_t *track);
void transport_sent_cache_destroy(transport_sent_cache_t *cache);

typedef struct {
  fec_type_t type;
  size_t data_symbols;
  size_t parity_symbols;
  size_t symbol_size;
  fec_t *fec;
  uint64_t last_used_ns;
} transport_fec_cache_entry_t;

typedef struct {
  transport_fec_cache_entry_t entries[TRANSPORT_FEC_CACHE_SIZE];
} transport_fec_cache_t;

fec_t *transport_fec_cache_get(transport_fec_cache_t *cache, fec_type_t type,
                               size_t data_symbols, size_t parity_symbols,
                               size_t symbol_size);
void transport_fec_cache_destroy(transport_fec_cache_t *cache);

#endif
