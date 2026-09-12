/* test_fec.c */

#include "fec.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int run_test(fec_type_t type, const char *name) {
  size_t data_symbols = 4;
  size_t parity_symbols = 2;
  size_t symbol_size = 100;
  size_t total_symbols = data_symbols + parity_symbols;
  int result = 1;
  fec_t *f = NULL;
  bool *missing = NULL;

  /* create data and parity buffers */
  uint8_t **data = calloc(data_symbols, sizeof(uint8_t *));
  uint8_t **parity = calloc(parity_symbols, sizeof(uint8_t *));
  uint8_t **blocks = calloc(total_symbols, sizeof(uint8_t *));
  uint8_t **orig_data = calloc(data_symbols, sizeof(uint8_t *));
  if (!data || !parity || !blocks || !orig_data) {
    fprintf(stderr, "failed to allocate FEC pointer arrays for %s\n", name);
    goto cleanup;
  }

  for (size_t i = 0; i < data_symbols; i++) {
    data[i] = malloc(symbol_size);
    orig_data[i] = malloc(symbol_size);
    blocks[i] = malloc(symbol_size);
    if (!data[i] || !orig_data[i] || !blocks[i]) {
      fprintf(stderr, "failed to allocate FEC data blocks for %s\n", name);
      goto cleanup;
    }
    /* populate with deterministic test patterns */
    for (size_t j = 0; j < symbol_size; j++) {
      data[i][j] = (uint8_t)(i * 17 + j * 3);
    }
    memcpy(orig_data[i], data[i], symbol_size);
    memcpy(blocks[i], data[i], symbol_size);
  }

  for (size_t i = 0; i < parity_symbols; i++) {
    parity[i] = malloc(symbol_size);
    blocks[data_symbols + i] = malloc(symbol_size);
    if (!parity[i] || !blocks[data_symbols + i]) {
      fprintf(stderr, "failed to allocate FEC parity blocks for %s\n", name);
      goto cleanup;
    }
  }

  /* create fec context and encode */
  f = fec_create_ex(type, data_symbols, parity_symbols, symbol_size);
  if (!f) {
    fprintf(stderr, "failed to create fec context for %s\n", name);
    goto cleanup;
  }

  if (!fec_encode(f, (const uint8_t *const *)data, parity)) {
    fprintf(stderr, "fec encoding failed for %s\n", name);
    goto cleanup;
  }

  /* copy parity symbols into blocks array */
  for (size_t i = 0; i < parity_symbols; i++) {
    memcpy(blocks[data_symbols + i], parity[i], symbol_size);
  }

  /* simulate packet loss: erase block 1 (data) and block 4 (parity) */
  missing = calloc(total_symbols, sizeof(bool));
  if (!missing) {
    fprintf(stderr, "failed to allocate FEC missing mask for %s\n", name);
    goto cleanup;
  }
  missing[1] = true;
  missing[data_symbols] = true; /* first parity symbol */

  memset(blocks[1], 0, symbol_size);
  memset(blocks[data_symbols], 0, symbol_size);

  /* decode to recover missing blocks */
  if (!fec_decode(f, blocks, missing)) {
    fprintf(stderr, "fec decoding failed for %s\n", name);
    goto cleanup;
  }

  /* verify recovered data */
  if (memcmp(blocks[1], orig_data[1], symbol_size) != 0) {
    fprintf(
        stderr,
        "fec validation failed for %s: block 1 data not recovered correctly\n",
        name);
    goto cleanup;
  }

  printf("%s validation OK\n", name);
  result = 0;

cleanup:
  fec_destroy(f);
  free(missing);
  for (size_t i = 0; i < data_symbols; i++) {
    free(data ? data[i] : NULL);
    free(orig_data ? orig_data[i] : NULL);
    free(blocks ? blocks[i] : NULL);
  }
  for (size_t i = 0; i < parity_symbols; i++) {
    free(parity ? parity[i] : NULL);
    free(blocks ? blocks[data_symbols + i] : NULL);
  }
  free(data);
  free(parity);
  free(blocks);
  free(orig_data);

  return result;
}

static int test_raptorq_extra_equations(void) {
  enum { K = 32, P = 8, T = 100 };
  uint8_t original[K + P][T], received[K + P][T];
  uint8_t *data[K + P], *blocks[K + P];
  bool missing[K + P] = {false};
  fec_t *f = fec_create_ex(FEC_RAPTORQ, K, P, T);
  if (!f)
    return 1;
  for (size_t i = 0; i < K + P; ++i) {
    data[i] = original[i];
    blocks[i] = received[i];
    for (size_t j = 0; j < T; ++j)
      original[i][j] = (uint8_t)(i * 17 + j * 3);
  }
  int result = 1;
  if (!fec_encode(f, (const uint8_t *const *)data, data + K))
    goto cleanup;
  memcpy(received, original, sizeof(received));
  missing[0] = missing[5] = missing[22] = true;
  memset(received[0], 0, T);
  memset(received[5], 0, T);
  memset(received[22], 0, T);
  for (size_t i = K + 3; i < K + P; ++i)
    missing[i] = true;
  /* These three repair equations are rank deficient for this erasure pattern.
   * New equations must participate in subsequent attempts, including the
   * extra rows beyond RaptorQ's padded K-prime source block. */
  if (fec_decode(f, blocks, missing)) {
    fprintf(stderr, "rank-deficient RaptorQ subset unexpectedly decoded\n");
    goto cleanup;
  }
  for (size_t i = K + 3; i < K + P; ++i)
    missing[i] = false;
  if (!fec_decode(f, blocks, missing) ||
      memcmp(received, original, K * T) != 0) {
    fprintf(stderr, "additional RaptorQ repairs did not recover all data\n");
    goto cleanup;
  }
  /* Reuse the expanded workspace for encoding and a smaller decode. */
  if (!fec_encode(f, (const uint8_t *const *)blocks, blocks + K) ||
      memcmp(received + K, original + K, P * T) != 0)
    goto cleanup;
  memset(missing, 0, sizeof(missing));
  missing[1] = true;
  for (size_t i = K + 1; i < K + P; ++i)
    missing[i] = true;
  memset(received[1], 0, T);
  if (!fec_decode(f, blocks, missing) || memcmp(received, original, K * T) != 0)
    goto cleanup;
  result = 0;
  printf("RaptorQ additional equations and workspace reuse OK\n");
cleanup:
  fec_destroy(f);
  return result;
}

static int test_short_symbols(void) {
  const size_t sizes[] = {1, 3, 31, 257, 999, 1000, 1199, 1200};
  for (size_t type = 0; type < 2; type++) {
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
      size_t size = sizes[i];
      fec_t *fec =
          fec_create_ex(type == 0 ? FEC_REED_SOLOMON : FEC_RAPTORQ, 1, 4, size);
      uint8_t *blocks[5] = {0};
      uint8_t *original = malloc(size);
      bool missing[5] = {true, false, false, false, false};
      int failed = fec == NULL || original == NULL;
      for (size_t j = 0; j < 5; j++) {
        blocks[j] = malloc(size);
        failed |= blocks[j] == NULL;
      }
      if (!failed) {
        for (size_t j = 0; j < size; j++)
          original[j] = blocks[0][j] = (uint8_t)(j * 17 + 91);
        failed = !fec_encode(fec, (const uint8_t *const *)blocks, blocks + 1);
        memset(blocks[0], 0, size);
        failed |= !fec_decode(fec, blocks, missing);
        failed |= memcmp(blocks[0], original, size) != 0;
      }
      fec_destroy(fec);
      free(original);
      for (size_t j = 0; j < 5; j++)
        free(blocks[j]);
      if (failed) {
        fprintf(stderr, "short FEC recovery failed: type=%zu size=%zu\n", type,
                size);
        return 1;
      }
    }
  }
  puts("Short unaligned single-symbol FEC recovery OK");
  return 0;
}

int main(void) {
  printf("running FEC test suite...\n");
  if (fec_create_ex((fec_type_t)99, 4, 2, 1024) != NULL ||
      fec_create_ex(FEC_REED_SOLOMON, 0, 2, 1024) != NULL ||
      fec_create_ex(FEC_REED_SOLOMON, 250, 10, 1024) != NULL) {
    fprintf(stderr, "invalid FEC parameters were accepted\n");
    return 1;
  }
  if (run_test(FEC_REED_SOLOMON, "Reed-Solomon") != 0)
    return 1;
  if (run_test(FEC_RAPTORQ, "RaptorQ") != 0)
    return 1;
  if (test_raptorq_extra_equations() != 0)
    return 1;
  if (test_short_symbols() != 0)
    return 1;
  printf("===FEC OK===\n");
  return 0;
}
