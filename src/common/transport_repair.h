#ifndef QLINQ_TRANSPORT_REPAIR_H
#define QLINQ_TRANSPORT_REPAIR_H

#include "transport_fec_state.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TRANSPORT_REPAIR_MAX_SYMBOLS 64U
#define TRANSPORT_REPAIR_SUPPRESSION_ENTRIES 64U

typedef struct {
  uint64_t tokens_milli;
  int64_t last_refill_ms;
} transport_repair_limiter_t;

typedef struct {
  bool active;
  uint64_t group_id;
  uint64_t object_id;
  uint64_t request_fingerprint;
  int64_t expires_at_ms;
} transport_repair_suppression_entry_t;

typedef struct {
  transport_repair_suppression_entry_t
      entries[TRANSPORT_REPAIR_SUPPRESSION_ENTRIES];
  size_t next_entry;
} transport_repair_suppression_t;

typedef struct {
  uint16_t indices[TRANSPORT_REPAIR_MAX_SYMBOLS];
  uint8_t *symbols;
  size_t count;
  uint16_t total_symbols;
  uint16_t symbol_size;
} transport_repair_batch_t;

bool transport_repair_build(transport_fec_cache_t *fec_cache,
                            const sent_object_cache_t *object,
                            bool whole_object, const uint16_t *missing,
                            size_t missing_count,
                            transport_repair_batch_t *batch);
/* Builds up to requested fresh RaptorQ ESIs without consuming them. The caller
 * commits only the prefix actually admitted to an egress queue. */
bool transport_repair_build_rateless(transport_fec_cache_t *fec_cache,
                                     sent_object_cache_t *object,
                                     size_t requested,
                                     transport_repair_batch_t *batch);
bool transport_repair_commit_rateless(sent_object_cache_t *object,
                                      const transport_repair_batch_t *batch,
                                      size_t admitted);
/* Once the bounded repair ESI namespace is exhausted, cycle retained source
 * symbols. Repeated deficit feedback will eventually cover every systematic
 * symbol, providing a finite-state correctness fallback. */
bool transport_repair_build_systematic_fallback(
    transport_fec_cache_t *fec_cache, sent_object_cache_t *object,
    size_t requested, transport_repair_batch_t *batch);
bool transport_repair_commit_systematic_fallback(
    sent_object_cache_t *object, const transport_repair_batch_t *batch,
    size_t admitted);
void transport_repair_batch_destroy(transport_repair_batch_t *batch);

/* Smooth token bucket used for receiver and source-wide feedback failsafes.
 * One token represents one repair request. */
uint64_t transport_repair_limiter_wait_ms(transport_repair_limiter_t *limiter,
                                          size_t requests_per_second,
                                          int64_t now_ms);
bool transport_repair_limiter_take(transport_repair_limiter_t *limiter,
                                   size_t requests_per_second, int64_t now_ms);

uint64_t transport_repair_request_fingerprint(uint8_t flags,
                                              const uint16_t *indices,
                                              size_t count);
/* Sorts indices in place and removes duplicates, returning the new count. */
size_t transport_repair_normalize_indices(uint16_t *indices, size_t count);
bool transport_repair_suppression_contains(
    const transport_repair_suppression_t *suppression, uint64_t group_id,
    uint64_t object_id, uint64_t request_fingerprint, int64_t now_ms);
void transport_repair_suppression_record(
    transport_repair_suppression_t *suppression, uint64_t group_id,
    uint64_t object_id, uint64_t request_fingerprint, int64_t expires_at_ms);

#endif
