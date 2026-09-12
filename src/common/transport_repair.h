#ifndef QLINQ_TRANSPORT_REPAIR_H
#define QLINQ_TRANSPORT_REPAIR_H

#include "transport_fec_state.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TRANSPORT_REPAIR_MAX_SYMBOLS 64U

typedef struct {
  uint64_t tokens_milli;
  int64_t last_refill_ms;
} transport_repair_limiter_t;

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
bool transport_repair_build_rateless(transport_fec_cache_t *fec_cache,
                                     sent_object_cache_t *object,
                                     size_t requested,
                                     transport_repair_batch_t *batch);
bool transport_repair_commit_rateless(sent_object_cache_t *object,
                                      const transport_repair_batch_t *batch,
                                      size_t admitted);
bool transport_repair_build_systematic_fallback(
    transport_fec_cache_t *fec_cache, sent_object_cache_t *object,
    size_t requested, transport_repair_batch_t *batch);
bool transport_repair_commit_systematic_fallback(
    sent_object_cache_t *object, const transport_repair_batch_t *batch,
    size_t admitted);
void transport_repair_batch_destroy(transport_repair_batch_t *batch);

/* Inspect admission without spending a token; UINT64_MAX means disabled. */
uint64_t transport_repair_limiter_wait_ms(transport_repair_limiter_t *limiter,
                                          size_t requests_per_second,
                                          int64_t now_ms);
bool transport_repair_limiter_take(transport_repair_limiter_t *limiter,
                                   size_t requests_per_second, int64_t now_ms);
size_t transport_repair_normalize_indices(uint16_t *indices, size_t count);

#endif
