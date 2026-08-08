/* fec.c */

#include "fec.h"
#include "rs.h"
#include <nanorq_core.h>
#include <nanorq_ops.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

struct fec_t {
  fec_type_t type;
  reed_solomon *rs;
  size_t data_symbols;
  size_t parity_symbols;
  size_t symbol_size;
  uint8_t **shards;
  uint8_t *marks;

  /* raptorq preallocated buffers for thread-safety and zero-allocation hot path
   */
  uint8_t *rq_src_data;
  uint8_t *rq_repair_out;
  uint8_t *rq_prep_mem;
  uint8_t *rq_work_mem;
  sched_op *rq_ops;
  uint8_t *rq_D;
  uint32_t *rq_dropped_esi;
  uint32_t *rq_repair_esi;
};

fec_t *fec_create_ex(fec_type_t type, size_t data_symbols,
                     size_t parity_symbols, size_t symbol_size) {
  fec_t *f = calloc(1, sizeof(fec_t));
  if (!f)
    return NULL;

  f->type = type;
  f->data_symbols = data_symbols;
  f->parity_symbols = parity_symbols;
  f->symbol_size = symbol_size;

  if (type == FEC_REED_SOLOMON) {
#ifndef _WIN32
    static pthread_once_t rs_once = PTHREAD_ONCE_INIT;
    pthread_once(&rs_once, reed_solomon_init);
#else
    static bool rs_initialized = false;
    if (!rs_initialized) {
      reed_solomon_init();
      rs_initialized = true;
    }
#endif
    f->rs = reed_solomon_new(data_symbols, parity_symbols);
    if (!f->rs) {
      free(f);
      return NULL;
    }
    size_t total_symbols = data_symbols + parity_symbols;
    f->shards = calloc(total_symbols, sizeof(uint8_t *));
    f->marks = calloc(total_symbols, sizeof(uint8_t));
    if (!f->shards || !f->marks) {
      fec_destroy(f);
      return NULL;
    }
  } else if (type == FEC_RAPTORQ) {
    f->rq_src_data = malloc(data_symbols * symbol_size);
    f->rq_repair_out = malloc(parity_symbols * symbol_size);

    struct nanorq_core_mem_reqs reqs;
    nanorq_core_get_memory_reqs(data_symbols, 0, symbol_size, &reqs);

    f->rq_prep_mem = malloc(reqs.prepare_bytes);
    f->rq_work_mem = malloc(reqs.work_bytes);
    f->rq_ops = malloc(reqs.schedule_bytes);
    f->rq_D = malloc(reqs.matrix_bytes);

    f->rq_dropped_esi = malloc(data_symbols * sizeof(uint32_t));
    f->rq_repair_esi = malloc(parity_symbols * sizeof(uint32_t));

    if (!f->rq_src_data || !f->rq_repair_out || !f->rq_prep_mem ||
        !f->rq_work_mem || !f->rq_ops || !f->rq_D || !f->rq_dropped_esi ||
        !f->rq_repair_esi) {
      fec_destroy(f);
      return NULL;
    }
  }

  return f;
}

fec_t *fec_create(size_t data_symbols, size_t parity_symbols,
                  size_t symbol_size) {
  return fec_create_ex(FEC_REED_SOLOMON, data_symbols, parity_symbols,
                       symbol_size);
}

void fec_destroy(fec_t *f) {
  if (f) {
    if (f->rs)
      reed_solomon_release(f->rs);
    free(f->shards);
    free(f->marks);

    free(f->rq_src_data);
    free(f->rq_repair_out);
    free(f->rq_prep_mem);
    free(f->rq_work_mem);
    free(f->rq_ops);
    free(f->rq_D);
    free(f->rq_dropped_esi);
    free(f->rq_repair_esi);

    free(f);
  }
}

void fec_encode(fec_t *f, const uint8_t *const *data_blocks,
                uint8_t *const *parity_blocks) {
  if (!f)
    return;

  if (f->type == FEC_REED_SOLOMON) {
    size_t total_symbols = f->data_symbols + f->parity_symbols;
    /* populate shards array */
    for (size_t i = 0; i < f->data_symbols; i++) {
      f->shards[i] = (uint8_t *)data_blocks[i];
    }
    for (size_t i = 0; i < f->parity_symbols; i++) {
      f->shards[f->data_symbols + i] = parity_blocks[i];
    }
    reed_solomon_encode(f->rs, f->shards, total_symbols, f->symbol_size);
  } else if (f->type == FEC_RAPTORQ) {
    /* dynamic raptorq core encoding using preallocated context buffers */
    nanorq_core enc;
    if (!nanorq_core_encoder_new(f->data_symbols, 0, &enc)) {
      return;
    }

    struct nanorq_core_mem_reqs reqs;
    nanorq_core_get_memory_reqs(f->data_symbols, 0, f->symbol_size, &reqs);

    if (!nanorq_core_prepare(&enc, f->rq_prep_mem, reqs.prepare_bytes)) {
      return;
    }

    uint8_t *D = f->rq_D;
    memset(D, 0, reqs.matrix_bytes);

    uint32_t SH = nanorq_core_get_pc_genc_offset(&enc);

    for (size_t i = 0; i < f->data_symbols; i++) {
      memcpy(D + (SH + i) * f->symbol_size, data_blocks[i], f->symbol_size);
    }

    schedule S_enc = {0};
    S_enc.ops.a = f->rq_ops;
    S_enc.ops.m = reqs.schedule_bytes / sizeof(sched_op);

    nanorq_core_set_op_callback(&enc, &S_enc, ops_push);

    if (!nanorq_core_precalculate(&enc, f->rq_work_mem, reqs.work_bytes)) {
      return;
    }

    ops_run(&enc, D, f->symbol_size, &S_enc);

    for (size_t i = 0; i < f->parity_symbols; i++) {
      ops_mix(&enc, D, f->symbol_size, f->data_symbols + i, parity_blocks[i]);
    }
  }
}

bool fec_decode(fec_t *f, uint8_t *const *blocks, const bool *missing_mask) {
  if (!f)
    return false;

  if (f->type == FEC_REED_SOLOMON) {
    size_t total_symbols = f->data_symbols + f->parity_symbols;
    /* populate shards and erasure marks */
    for (size_t i = 0; i < total_symbols; i++) {
      f->shards[i] = blocks[i];
      f->marks[i] = missing_mask[i] ? 1 : 0;
    }
    int res = reed_solomon_decode(f->rs, f->shards, f->marks, total_symbols,
                                  f->symbol_size);
    return res == 0;
  } else if (f->type == FEC_RAPTORQ) {
    /* dynamic raptorq core decoding using preallocated context buffers */
    size_t drops = 0;
    uint32_t *dropped_esi = f->rq_dropped_esi;
    for (size_t i = 0; i < f->data_symbols; i++) {
      if (missing_mask[i]) {
        dropped_esi[drops++] = i;
      }
    }

    size_t available_repairs = 0;
    uint32_t *repair_esi = f->rq_repair_esi;
    for (size_t i = 0; i < f->parity_symbols; i++) {
      if (!missing_mask[f->data_symbols + i]) {
        repair_esi[available_repairs++] = f->data_symbols + i;
      }
    }

    if (drops > available_repairs) {
      return false;
    }

    if (drops == 0) {
      return true;
    }

    nanorq_core dec;
    if (!nanorq_core_encoder_new(f->data_symbols, 0, &dec)) {
      return false;
    }

    struct nanorq_core_mem_reqs reqs;
    nanorq_core_get_memory_reqs(f->data_symbols, 0, f->symbol_size, &reqs);

    if (!nanorq_core_prepare(&dec, f->rq_prep_mem, reqs.prepare_bytes)) {
      return false;
    }

    for (size_t i = 0; i < drops; i++) {
      nanorq_core_replace_symbol(&dec, dropped_esi[i], repair_esi[i]);
    }
    nanorq_core_patch_matrix(&dec);

    schedule S_dec = {0};
    S_dec.ops.a = f->rq_ops;
    S_dec.ops.m = reqs.schedule_bytes / sizeof(sched_op);

    nanorq_core_set_op_callback(&dec, &S_dec, ops_push);

    if (!nanorq_core_precalculate(&dec, f->rq_work_mem, reqs.work_bytes)) {
      return false;
    }

    uint8_t *D = f->rq_D;
    memset(D, 0, reqs.matrix_bytes);

    uint32_t SH = nanorq_core_get_pc_genc_offset(&dec);

    for (size_t i = 0; i < f->data_symbols; i++) {
      if (!missing_mask[i]) {
        memcpy(D + (SH + i) * f->symbol_size, blocks[i], f->symbol_size);
      }
    }
    for (size_t i = 0; i < drops; i++) {
      uint32_t src_esi = dropped_esi[i];
      uint32_t rep_esi = repair_esi[i];
      memcpy(D + (SH + src_esi) * f->symbol_size, blocks[rep_esi],
             f->symbol_size);
    }

    ops_run(&dec, D, f->symbol_size, &S_dec);

    for (size_t i = 0; i < drops; i++) {
      uint32_t src_esi = dropped_esi[i];
      ops_mix(&dec, D, f->symbol_size, src_esi, blocks[src_esi]);
    }

    return true;
  }

  return false;
}
