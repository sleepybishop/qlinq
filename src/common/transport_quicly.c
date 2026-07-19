/* transport_quicly.c */

#include "fec.h"
#include "ifmon.h"
#include "pathflow.h"
#include "portable_sockets.h"
#include "transport.h"
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/errqueue.h>
#include <openssl/pem.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifndef _WIN32
#include <net/if.h>
#endif

#include "pathflow.h"
#include "picotls.h"
#include "picotls/openssl.h"
#include "quicly.h"
#include "quicly/defaults.h"
#include "quicly/sendstate.h"
#include "quicly/streambuf.h"

static uint64_t get_time_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

#define MAX_CONNECTIONS 32
#define ASSEMBLER_CACHE_SIZE 16

#define SENT_CACHE_SIZE 32

typedef struct {
  uint8_t track_id;
  uint32_t group_id;
  uint32_t object_id;
  uint16_t total_symbols;
  uint16_t data_symbols;
  uint16_t symbol_size;
  uint32_t original_size;
  uint16_t received_count;
  uint16_t capacity_symbols;
  uint16_t capacity_symbol_size;
  uint8_t **buffers;
  bool *received_mask;
  uint16_t *missing_indices;
  bool decoded;
  uint8_t priority;
  bool nack_sent;
} frame_assembler_t;

#define ARENA_MAX_FALLBACKS 1024

typedef struct {
  uint8_t *buffer;
  size_t capacity;
  size_t offset;
  void *fallbacks[ARENA_MAX_FALLBACKS];
  size_t fallback_count;
} arena_t;

static void *arena_alloc(arena_t *a, size_t size) {
  size = (size + 7) & ~7;
  if (a->offset + size > a->capacity) {
    void *ptr = malloc(size);
    if (ptr && a->fallback_count < ARENA_MAX_FALLBACKS) {
      a->fallbacks[a->fallback_count++] = ptr;
    }
    return ptr;
  }
  void *ptr = a->buffer + a->offset;
  a->offset += size;
  memset(ptr, 0, size);
  return ptr;
}

static void arena_reset(arena_t *a) {
  a->offset = 0;
  for (size_t i = 0; i < a->fallback_count; i++) {
    free(a->fallbacks[i]);
  }
  a->fallback_count = 0;
}

typedef struct {
  moq_track_id_t track_id;
  uint32_t group_id;
  uint32_t object_id;
  uint8_t *data;
  size_t size;
  uint8_t priority;
  bool is_keyframe;
  uint16_t total_symbols;
  uint16_t data_symbols;
  uint16_t symbol_size;
} sent_object_cache_t;

#define FEC_CACHE_SIZE 8

typedef struct {
  fec_type_t type;
  size_t data_symbols;
  size_t parity_symbols;
  size_t symbol_size;
  fec_t *fec;
  uint64_t last_used_ns;
} fec_cache_entry_t;

struct transport_t {
  transport_callback_t callback;
  void *user_data;
  bool is_server;
  int fds[TRANSPORT_MAX_PATHS];
  size_t num_fds;
  struct sockaddr_storage local_addrs[TRANSPORT_MAX_PATHS];
  socklen_t local_addrs_len[TRANSPORT_MAX_PATHS];

  /* client connection */
  struct sockaddr_storage remote_addrs[TRANSPORT_MAX_PATHS];
  socklen_t remote_addrs_len[TRANSPORT_MAX_PATHS];
  size_t num_remote_addrs;
  quicly_context_t quic_ctx;
  ptls_context_t tls_ctx;
  ptls_openssl_sign_certificate_t sign_cert;
  quicly_cid_plaintext_t next_cid;

  path_state_t path_states[TRANSPORT_MAX_PATHS];
  uint64_t last_pathflow_update;

  int64_t min_owd_ns[TRANSPORT_MAX_PATHS];
  fp_t latest_owd_fp[TRANSPORT_MAX_PATHS];
  uint64_t last_telemetry_s_ns[TRANSPORT_MAX_PATHS];
  uint64_t last_telemetry_r_ns[TRANSPORT_MAX_PATHS];

  /* server connections list */
  transport_conn_t *conns[MAX_CONNECTIONS];
  size_t conn_count;

  /* client connection */
  transport_conn_t *client_conn;

  /* stream open callback payload */
  quicly_stream_open_t stream_open;
  ptls_openssl_verify_certificate_t verifier;
  bool verifier_initialized;
  quicly_receive_datagram_frame_t receive_datagram;

  /* sent object history cache for NACK retransmissions */
  sent_object_cache_t sent_cache[SENT_CACHE_SIZE];
  size_t sent_cache_index;

  /* simulated packet loss */
  uint8_t simulated_loss_rate;

  /* pre-allocated transport memory arena */
  arena_t arena;

  /* FEC Packet Grouping Buffer */
  uint8_t *fec_buf;
  size_t fec_buf_len;
  size_t fec_buf_cap;
  uint64_t fec_first_pkt_time;
  moq_track_id_t fec_track_id;
  uint32_t fec_object_id;
  uint32_t fec_pkt_count;
  uint8_t fec_priority;
  bool fec_in_flush;

  /* ifmon integration */
  ifmon_watcher_t ifmon_w;
  int ifmon_pipe[2];

  /* fec cache for zero-allocation hot path */
  fec_cache_entry_t fec_cache[FEC_CACHE_SIZE];
};

/* fetch or create a cached FEC context matching parameters */
static fec_t *get_cached_fec(transport_t *t, fec_type_t type,
                             size_t data_symbols, size_t parity_symbols,
                             size_t symbol_size) {
  uint64_t now = get_time_ns();
  int lru_idx = 0;
  uint64_t min_time = -1;

  for (int i = 0; i < FEC_CACHE_SIZE; i++) {
    if (t->fec_cache[i].fec && t->fec_cache[i].type == type &&
        t->fec_cache[i].data_symbols == data_symbols &&
        t->fec_cache[i].parity_symbols == parity_symbols &&
        t->fec_cache[i].symbol_size == symbol_size) {
      t->fec_cache[i].last_used_ns = now;
      return t->fec_cache[i].fec;
    }
    if (t->fec_cache[i].last_used_ns < min_time) {
      min_time = t->fec_cache[i].last_used_ns;
      lru_idx = i;
    }
  }

  /* cache miss, evict the lru entry */
  if (t->fec_cache[lru_idx].fec) {
    fec_destroy(t->fec_cache[lru_idx].fec);
    t->fec_cache[lru_idx].fec = NULL;
  }

  fec_t *fec = fec_create_ex(type, data_symbols, parity_symbols, symbol_size);
  if (fec) {
    t->fec_cache[lru_idx].type = type;
    t->fec_cache[lru_idx].data_symbols = data_symbols;
    t->fec_cache[lru_idx].parity_symbols = parity_symbols;
    t->fec_cache[lru_idx].symbol_size = symbol_size;
    t->fec_cache[lru_idx].fec = fec;
    t->fec_cache[lru_idx].last_used_ns = now;
  }
  return fec;
}

/* Helper to map a link/socket index to the QUIC path index by matching local
 * IPs */
static size_t find_path_index_by_link(quicly_conn_t *quic, transport_t *t,
                                      size_t link_idx) {
  if (link_idx >= t->num_fds)
    return 0;

  struct sockaddr_in *link_loc =
      (struct sockaddr_in *)&t->local_addrs[link_idx];
  if (link_loc->sin_family != AF_INET)
    return 0;

  for (size_t p = 0; p < 8; p++) { /* 8 is the max paths limit */
    quicly_path_stats_t stats;
    if (quicly_get_path_stats(quic, p, &stats) == 0) {
      struct sockaddr_in *path_loc = (struct sockaddr_in *)&stats.local;
      if (path_loc->sin_family == AF_INET &&
          path_loc->sin_addr.s_addr == link_loc->sin_addr.s_addr) {
        return p;
      }
    }
  }
  return 0;
}

typedef struct {
  moq_track_id_t track_id;
  uint8_t alias;
  bool active;
  quicly_stream_t *stream;
} track_subscription_t;

struct transport_conn_t {
  transport_t *transport;
  quicly_conn_t *quic;
  uint32_t id;
  track_subscription_t subscriptions[32];
  bool handshake_complete;
  bool authenticated;

  /* client control stream */
  quicly_stream_t *stream;

  /* incoming datagram assembler cache */
  frame_assembler_t assemblers[ASSEMBLER_CACHE_SIZE];
  size_t assembler_index;
};

static int find_subscription_by_alias(const transport_conn_t *conn,
                                      uint8_t alias,
                                      moq_track_id_t *out_track) {
  if (alias < 8) {
    out_track->type = (moq_track_type_t)alias;
    out_track->name[0] = '\0';
    return 0;
  }
  for (int i = 0; i < 32; i++) {
    if (conn->subscriptions[i].active &&
        conn->subscriptions[i].alias == alias) {
      *out_track = conn->subscriptions[i].track_id;
      return 0;
    }
  }
  return -1;
}

static int find_alias_by_track(const transport_conn_t *conn,
                               const moq_track_id_t *track,
                               uint8_t *out_alias) {
  if (track->name[0] == '\0') {
    *out_alias = (uint8_t)track->type;
    return 0;
  }
  for (int i = 0; i < 32; i++) {
    if (conn->subscriptions[i].active &&
        conn->subscriptions[i].track_id.type == track->type &&
        strcmp(conn->subscriptions[i].track_id.name, track->name) == 0) {
      *out_alias = conn->subscriptions[i].alias;
      return 0;
    }
  }
  return -1;
}

static bool is_subscribed(const transport_conn_t *conn,
                          const moq_track_id_t *track) {
  uint8_t dummy;
  return find_alias_by_track(conn, track, &dummy) == 0;
}

static void add_subscription(transport_conn_t *conn, moq_track_type_t type,
                             uint8_t flags, const char *name, uint8_t alias) {
  for (int i = 0; i < 32; i++) {
    if (conn->subscriptions[i].active &&
        conn->subscriptions[i].track_id.type == type &&
        strcmp(conn->subscriptions[i].track_id.name, name) == 0) {
      conn->subscriptions[i].alias = alias;
      conn->subscriptions[i].track_id.flags = flags;
      return;
    }
  }
  for (int i = 0; i < 32; i++) {
    if (!conn->subscriptions[i].active) {
      conn->subscriptions[i].track_id.type = type;
      conn->subscriptions[i].track_id.flags = flags;
      strncpy(conn->subscriptions[i].track_id.name, name,
              sizeof(conn->subscriptions[i].track_id.name) - 1);
      conn->subscriptions[i]
          .track_id.name[sizeof(conn->subscriptions[i].track_id.name) - 1] =
          '\0';
      conn->subscriptions[i].alias = alias;
      conn->subscriptions[i].active = true;
      conn->subscriptions[i].stream = NULL;
      return;
    }
  }
}

static void remove_subscription(transport_conn_t *conn, moq_track_type_t type,
                                const char *name) {
  for (int i = 0; i < 32; i++) {
    if (conn->subscriptions[i].active &&
        conn->subscriptions[i].track_id.type == type &&
        strcmp(conn->subscriptions[i].track_id.name, name) == 0) {
      conn->subscriptions[i].active = false;
      if (conn->subscriptions[i].stream) {
        quicly_streambuf_egress_shutdown(conn->subscriptions[i].stream);
        conn->subscriptions[i].stream = NULL;
      }
      return;
    }
  }
}

typedef struct __attribute__((packed)) {
  uint8_t track_id;
  uint8_t is_keyframe;
  uint8_t priority;
  uint32_t group_id;
  uint32_t object_id;
  uint16_t symbol_index;
  uint16_t total_symbols;
  uint16_t data_symbols;
  uint16_t symbol_size;
  uint32_t original_size;
  uint8_t path_id;
  uint64_t send_time_ns;
} fec_packet_header_t;

typedef struct __attribute__((packed)) {
  uint8_t track_id;
  uint8_t path_id;
  uint64_t send_time_ns;
  uint64_t recv_time_ns;
} telemetry_datagram_t;

static const uint16_t verify_algos[] = {
    PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256, PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256,
    PTLS_SIGNATURE_RSA_PKCS1_SHA256, UINT16_MAX};

/* dummy verifier for local testing */
static int verify_certificate_cb(
    ptls_verify_certificate_t *self, ptls_t *tls, const char *server_name,
    int (**verify_sign)(void *verify_ctx, uint16_t algo, ptls_iovec_t data,
                        ptls_iovec_t sign),
    void **verify_data, ptls_iovec_t *certs, size_t num_certs) {
  (void)self;
  (void)tls;
  (void)server_name;
  (void)verify_sign;
  (void)verify_data;
  (void)certs;
  (void)num_certs;
  return 0;
}

/* parse control stream signaling messages */
static void parse_control_messages(transport_t *t, transport_conn_t *conn,
                                   quicly_stream_t *stream) {
  while (1) {
    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);
    if (input.len == 0)
      break;

    uint8_t type = input.base[0];
    if (type == 0x01 || type == 0x02 || type == 0x06) {
      if (input.len < 5)
        break;

      if (t->is_server && !conn->authenticated) {
        quicly_close(conn->quic, 0, "unauthorized");
        break;
      }

      uint8_t alias = input.base[1];
      uint8_t track_type = input.base[2];
      uint8_t flags = input.base[3];
      uint8_t name_len = input.base[4];
      if (input.len < 5 + (size_t)name_len)
        break;

      char name[64];
      size_t copy_len = (name_len < 63) ? name_len : 63;
      memcpy(name, input.base + 5, copy_len);
      name[copy_len] = '\0';

      moq_track_id_t parsed_track = {.type = (moq_track_type_t)track_type,
                                     .flags = flags};
      strcpy(parsed_track.name, name);

      if (type == 0x01) {
        quicly_debug_printf(
            conn->quic,
            "Subscription mapping: track '%s' (type %d) mapped to alias %d",
            name, track_type, alias);
        add_subscription(conn, (moq_track_type_t)track_type, flags, name,
                         alias);
      } else if (type == 0x02) {
        remove_subscription(conn, (moq_track_type_t)track_type, name);
      }

      transport_event_type_t ev_type = TRANSPORT_EVENT_SUBSCRIBE;
      if (type == 0x02) {
        ev_type = TRANSPORT_EVENT_UNSUBSCRIBE;
      } else if (type == 0x06) {
        ev_type = TRANSPORT_EVENT_KEYFRAME_REQUEST;
      }

      transport_event_t ev = {
          .type = ev_type, .conn = conn, .track_id = parsed_track};
      t->callback(t->user_data, &ev);
      quicly_streambuf_ingress_shift(stream, 5 + name_len);
    } else if (type == 0x03) {
      if (input.len < 5)
        break;

      uint32_t payload_size;
      memcpy(&payload_size, input.base + 1, 4);
      payload_size = be32toh(payload_size);

      if (payload_size > 1048576) {
        quicly_close(conn->quic, 0, "protocol error: payload too large");
        break;
      }

      if (input.len < 5 + payload_size)
        break;

      if (t->is_server && !conn->authenticated) {
        quicly_close(conn->quic, 0, "unauthorized");
        break;
      }

      transport_event_t ev = {.type = TRANSPORT_EVENT_OBJECT,
                              .conn = conn,
                              .track_id = {.type = MOQ_TRACK_INPUT},
                              .object = {.track_id = {.type = MOQ_TRACK_INPUT},
                                         .group_id = 0,
                                         .object_id = 0,
                                         .data = input.base + 5,
                                         .size = payload_size,
                                         .is_keyframe = false}};
      t->callback(t->user_data, &ev);
      quicly_streambuf_ingress_shift(stream, 5 + payload_size);
    } else if (type == 0x04) {
      if (input.len < 3)
        break;

      uint16_t token_len;
      memcpy(&token_len, input.base + 1, 2);
      token_len = be16toh(token_len);

      if (input.len < 3 + (size_t)token_len)
        break;

      transport_event_t ev = {.type = TRANSPORT_EVENT_AUTH,
                              .conn = conn,
                              .auth = {.token = input.base + 3,
                                       .token_len = token_len,
                                       .success = false}};
      t->callback(t->user_data, &ev);
      quicly_streambuf_ingress_shift(stream, 3 + token_len);
    } else if (type == 0x05) {
      if (input.len < 2)
        break;

      uint8_t status = input.base[1];
      if (status == 1) {
        conn->authenticated = true;
      }
      transport_event_t ev = {
          .type = TRANSPORT_EVENT_AUTH_COMPLETE,
          .conn = conn,
          .auth = {.token = NULL, .token_len = 0, .success = (status == 1)}};
      t->callback(t->user_data, &ev);
      quicly_streambuf_ingress_shift(stream, 2);
    } else if (type == 0x07) {
      if (input.len < 6)
        break;

      uint8_t alias = input.base[1];
      uint32_t payload_size;
      memcpy(&payload_size, input.base + 2, 4);
      payload_size = be32toh(payload_size);

      if (payload_size > 1048576) {
        quicly_close(conn->quic, 0, "protocol error: payload too large");
        break;
      }

      if (input.len < 6 + (size_t)payload_size)
        break;

      if (t->is_server && !conn->authenticated) {
        quicly_close(conn->quic, 0, "unauthorized");
        break;
      }

      moq_track_id_t resolved_track = {0};
      if (find_subscription_by_alias(conn, alias, &resolved_track) == 0) {
        resolved_track.flags &= ~MOQ_TRACK_FLAG_FEC_ENABLED;
        resolved_track.flags |= MOQ_TRACK_FLAG_RELIABLE;
        transport_event_t ev = {.type = TRANSPORT_EVENT_OBJECT,
                                .conn = conn,
                                .track_id = resolved_track,
                                .object = {.track_id = resolved_track,
                                           .group_id = 0,
                                           .object_id = 0,
                                           .data = input.base + 6,
                                           .size = payload_size,
                                           .is_keyframe = true}};
        t->callback(t->user_data, &ev);
      }
      quicly_streambuf_ingress_shift(stream, 6 + payload_size);
    } else if (type == 0x08) {
      if (input.len < 12)
        break;

      uint8_t alias = input.base[1];
      uint32_t group_id, object_id;
      uint16_t missing_count;
      memcpy(&group_id, input.base + 2, 4);
      memcpy(&object_id, input.base + 6, 4);
      memcpy(&missing_count, input.base + 10, 2);
      group_id = be32toh(group_id);
      object_id = be32toh(object_id);
      missing_count = be16toh(missing_count);

      if (input.len < 12 + (size_t)missing_count * 2)
        break;

      if (t->is_server && !conn->authenticated) {
        quicly_close(conn->quic, 0, "unauthorized");
        break;
      }

      if (missing_count > 256)
        missing_count = 256;
      uint16_t missing_indices[256];
      for (uint16_t i = 0; i < missing_count; i++) {
        uint16_t idx;
        memcpy(&idx, input.base + 12 + i * 2, 2);
        missing_indices[i] = be16toh(idx);
      }

      moq_track_id_t resolved_track;
      if (find_subscription_by_alias(conn, alias, &resolved_track) == 0) {
        sent_object_cache_t *cached = NULL;
        for (size_t i = 0; i < SENT_CACHE_SIZE; i++) {
          if (t->sent_cache[i].data &&
              t->sent_cache[i].track_id.type == resolved_track.type &&
              strcmp(t->sent_cache[i].track_id.name, resolved_track.name) ==
                  0 &&
              t->sent_cache[i].group_id == group_id &&
              t->sent_cache[i].object_id == object_id) {
            cached = &t->sent_cache[i];
            break;
          }
        }

        if (cached) {
          size_t data_symbols = cached->data_symbols;
          size_t total_symbols = cached->total_symbols;
          size_t parity_symbols = total_symbols - data_symbols;
          size_t symbol_size = cached->symbol_size;

          uint8_t **data_blocks = calloc(data_symbols, sizeof(uint8_t *));
          uint8_t **parity_blocks = calloc(parity_symbols, sizeof(uint8_t *));

          for (size_t i = 0; i < data_symbols; i++) {
            data_blocks[i] = calloc(1, symbol_size);
            size_t offset = i * symbol_size;
            size_t chunk =
                (offset < cached->size) ? (cached->size - offset) : 0;
            if (chunk > symbol_size)
              chunk = symbol_size;
            if (chunk > 0) {
              memcpy(data_blocks[i], cached->data + offset, chunk);
            }
          }

          for (size_t i = 0; i < parity_symbols; i++) {
            parity_blocks[i] = calloc(1, symbol_size);
          }

          if (parity_symbols > 0) {
            fec_type_t fec_type =
                (total_symbols > 255) ? FEC_RAPTORQ : FEC_REED_SOLOMON;
            fec_t *fec = get_cached_fec(t, fec_type, data_symbols,
                                        parity_symbols, symbol_size);
            if (fec) {
              fec_encode(fec, (const uint8_t *const *)data_blocks,
                         parity_blocks);
            }
          }

          for (size_t i = 0; i < missing_count; i++) {
            uint16_t s = missing_indices[i];
            if (s >= total_symbols)
              continue;

            size_t pkt_len = sizeof(fec_packet_header_t) + symbol_size;
            uint8_t pkt_buf[2048]; /* max datagram size */
            fec_packet_header_t *hdr = (fec_packet_header_t *)pkt_buf;

            hdr->track_id = alias;
            hdr->is_keyframe = cached->is_keyframe ? 1 : 0;
            hdr->priority = cached->priority;
            hdr->group_id = htobe32((uint32_t)cached->group_id);
            hdr->object_id = htobe32((uint32_t)cached->object_id);
            hdr->symbol_index = htobe16((uint16_t)s);
            hdr->total_symbols = htobe16((uint16_t)total_symbols);
            hdr->data_symbols = htobe16((uint16_t)data_symbols);
            hdr->symbol_size = htobe16((uint16_t)symbol_size);
            hdr->original_size = htobe32((uint32_t)cached->size);
            hdr->path_id = 0;
            hdr->send_time_ns = htobe64(get_time_ns());

            if (s < data_symbols) {
              memcpy(pkt_buf + sizeof(fec_packet_header_t), data_blocks[s],
                     symbol_size);
            } else {
              memcpy(pkt_buf + sizeof(fec_packet_header_t),
                     parity_blocks[s - data_symbols], symbol_size);
            }

            ptls_iovec_t dgram = ptls_iovec_init(pkt_buf, pkt_len);
            quicly_send_datagram_frames(conn->quic, &dgram, 1);
          }

          for (size_t i = 0; i < data_symbols; i++)
            free(data_blocks[i]);
          for (size_t i = 0; i < parity_symbols; i++)
            free(parity_blocks[i]);
          free(data_blocks);
          free(parity_blocks);
        }
      }
      quicly_streambuf_ingress_shift(stream, 12 + (size_t)missing_count * 2);
    } else {
      quicly_streambuf_ingress_shift(stream, 1);
    }
  }
}

typedef struct {
  quicly_streambuf_t streambuf;
  bool is_control;
  bool header_received;
  uint8_t alias;
} stream_ctx_t;

static void clear_subscription_stream(transport_conn_t *conn,
                                      quicly_stream_t *stream) {
  for (int i = 0; i < 32; i++) {
    if (conn->subscriptions[i].active &&
        conn->subscriptions[i].stream == stream) {
      conn->subscriptions[i].stream = NULL;
      break;
    }
  }
}

static void on_stream_destroy(quicly_stream_t *stream, quicly_error_t err) {
  transport_conn_t *conn = *quicly_get_data(stream->conn);
  if (conn) {
    clear_subscription_stream(conn, stream);
  }
  quicly_streambuf_destroy(stream, err);
}

static void parse_track_stream_messages(transport_t *t, transport_conn_t *conn,
                                        quicly_stream_t *stream) {
  stream_ctx_t *ctx = (stream_ctx_t *)stream->data;

  while (1) {
    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);
    if (input.len == 0)
      break;

    if (!ctx->header_received) {
      ctx->alias = input.base[0];
      ctx->header_received = true;
      quicly_streambuf_ingress_shift(stream, 1);

      /* Map client-side stream pointer back to subscription */
      for (int i = 0; i < 32; i++) {
        if (conn->subscriptions[i].active &&
            conn->subscriptions[i].alias == ctx->alias) {
          conn->subscriptions[i].stream = stream;
          quicly_debug_printf(conn->quic,
                              "Mapped incoming QUIC Stream %" PRIu64
                              " to MoQ track alias %d",
                              stream->stream_id, ctx->alias);
          break;
        }
      }

      input = quicly_streambuf_ingress_get(stream);
    }

    if (input.len < 4)
      break;

    uint32_t payload_size;
    memcpy(&payload_size, input.base, 4);
    payload_size = be32toh(payload_size);

    if (input.len < 4 + (size_t)payload_size)
      break;

    if (t->is_server && !conn->authenticated) {
      quicly_close(conn->quic, 0, "unauthorized");
      break;
    }

    moq_track_id_t resolved_track = {0};
    if (find_subscription_by_alias(conn, ctx->alias, &resolved_track) == 0) {
      transport_event_t ev = {.type = TRANSPORT_EVENT_OBJECT,
                              .conn = conn,
                              .track_id = resolved_track,
                              .object = {.track_id = resolved_track,
                                         .group_id = 0,
                                         .object_id = 0,
                                         .data = input.base + 4,
                                         .size = payload_size,
                                         .is_keyframe = true}};
      t->callback(t->user_data, &ev);
    }

    quicly_streambuf_ingress_shift(stream, 4 + payload_size);
  }
}

/* control stream receive callbacks */
static void on_receive(quicly_stream_t *stream, size_t off, const void *src,
                       size_t len) {
  if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0)
    return;

  transport_conn_t *conn = *quicly_get_data(stream->conn);
  if (conn) {
    stream_ctx_t *ctx = (stream_ctx_t *)stream->data;
    if (ctx->is_control) {
      parse_control_messages(conn->transport, conn, stream);
    } else {
      parse_track_stream_messages(conn->transport, conn, stream);
    }
  }
}

static void on_stop_sending(quicly_stream_t *stream, quicly_error_t err) {
  stream_ctx_t *ctx = (stream_ctx_t *)stream->data;
  if (ctx && ctx->is_control) {
    quicly_close(stream->conn, 0, "");
  } else {
    quicly_reset_stream(stream, err);
  }
}

static void on_receive_reset(quicly_stream_t *stream, quicly_error_t err) {
  stream_ctx_t *ctx = (stream_ctx_t *)stream->data;
  if (ctx && ctx->is_control) {
    quicly_close(stream->conn, 0, "");
  } else {
    quicly_reset_stream(stream, err);
  }
}

static quicly_error_t on_stream_open(quicly_stream_open_t *self,
                                     quicly_stream_t *stream) {
  (void)self;
  static const quicly_stream_callbacks_t stream_callbacks = {
      on_stream_destroy,
      quicly_streambuf_egress_shift,
      quicly_streambuf_egress_emit,
      on_stop_sending,
      on_receive,
      on_receive_reset};
  int ret;

  if ((ret = quicly_streambuf_create(stream, sizeof(stream_ctx_t))) != 0)
    return ret;
  stream->callbacks = &stream_callbacks;

  stream_ctx_t *ctx = (stream_ctx_t *)stream->data;
  ctx->is_control = (stream->stream_id == 0);
  ctx->header_received = false;
  ctx->alias = 0;

  /* client saves the stream pointer */
  transport_conn_t *conn = *quicly_get_data(stream->conn);
  if (conn && ctx->is_control) {
    conn->stream = stream;
  }

  return 0;
}

/* handle incoming datagram frames */
static void send_nack(transport_conn_t *conn, uint8_t alias, uint32_t group_id,
                      uint32_t object_id, uint16_t *missing, uint16_t count) {
  if (!conn || !conn->stream ||
      !quicly_sendstate_is_open(&conn->stream->sendstate))
    return;

  size_t payload_len = 12 + count * 2;
  uint8_t static_buf[1024];
  uint8_t *buf = static_buf;
  if (payload_len > sizeof(static_buf)) {
    buf = malloc(payload_len);
    if (!buf)
      return;
  }

  buf[0] = 0x08;
  buf[1] = alias;
  uint32_t g = htobe32(group_id);
  uint32_t o = htobe32(object_id);
  uint16_t c = htobe16(count);
  memcpy(buf + 2, &g, 4);
  memcpy(buf + 6, &o, 4);
  memcpy(buf + 10, &c, 2);
  for (uint16_t i = 0; i < count; i++) {
    uint16_t idx = htobe16(missing[i]);
    memcpy(buf + 12 + i * 2, &idx, 2);
  }
  quicly_streambuf_egress_write(conn->stream, buf, payload_len);

  if (buf != static_buf) {
    free(buf);
  }
}

static void on_receive_datagram_frame(quicly_receive_datagram_frame_t *self,
                                      quicly_conn_t *conn,
                                      ptls_iovec_t payload) {
  (void)self;
  transport_conn_t *tconn = *quicly_get_data(conn);
  if (!tconn)
    return;

  transport_t *t = tconn->transport;
  if (t->is_server && !tconn->authenticated)
    return;

  if (payload.len < 1)
    return;

  uint8_t track_id = ((uint8_t *)payload.base)[0];

  if (track_id == MOQ_TRACK_TELEMETRY) {
    if (payload.len < sizeof(telemetry_datagram_t))
      return;
    telemetry_datagram_t *t_hdr = (telemetry_datagram_t *)payload.base;
    uint8_t pid = t_hdr->path_id;
    if (pid < TRANSPORT_MAX_PATHS) {
      uint64_t s_ns = be64toh(t_hdr->send_time_ns);
      uint64_t r_ns = be64toh(t_hdr->recv_time_ns);

      /* relative owd (queuing delay estimation) */
      int64_t current_owd = (int64_t)r_ns - (int64_t)s_ns;
      if (t->min_owd_ns[pid] == 0 || current_owd < t->min_owd_ns[pid]) {
        t->min_owd_ns[pid] = current_owd;
      }
      int64_t relative_owd_ns = current_owd - t->min_owd_ns[pid];
      uint32_t relative_owd_us = relative_owd_ns / 1000;
      t->latest_owd_fp[pid] =
          FP_FROM_INT(relative_owd_us) / 1000000; /* convert us to seconds */

      t->last_telemetry_s_ns[pid] = s_ns;
      t->last_telemetry_r_ns[pid] = r_ns;
    }
    return;
  }

  if (payload.len < sizeof(fec_packet_header_t))
    return;

  fec_packet_header_t *hdr = (fec_packet_header_t *)payload.base;
  moq_track_id_t resolved_track;
  if (find_subscription_by_alias(tconn, track_id, &resolved_track) != 0) {
    return;
  }

  /* automatically send a telemetry reply to measure OWD */
  telemetry_datagram_t reply;
  reply.track_id = MOQ_TRACK_TELEMETRY;
  reply.path_id = hdr->path_id;
  reply.send_time_ns = hdr->send_time_ns; /* already network byte order */
  reply.recv_time_ns = htobe64(get_time_ns());
  ptls_iovec_t reply_vec;
  reply_vec.base = (uint8_t *)&reply;
  reply_vec.len = sizeof(reply);
  quicly_send_datagram_frames_path(conn, hdr->path_id, &reply_vec, 1);

  uint8_t is_keyframe = hdr->is_keyframe;
  uint32_t group_id = be32toh(hdr->group_id);
  uint32_t object_id = be32toh(hdr->object_id);
  uint16_t symbol_index = be16toh(hdr->symbol_index);
  uint16_t total_symbols = be16toh(hdr->total_symbols);
  uint16_t data_symbols = be16toh(hdr->data_symbols);
  uint16_t symbol_size = be16toh(hdr->symbol_size);
  uint32_t original_size = be32toh(hdr->original_size);

  if (total_symbols > 16384 || symbol_size > 4096)
    return;

  if (payload.len < sizeof(fec_packet_header_t) + symbol_size)
    return;

  /* lookup active frame assembler cache */
  frame_assembler_t *asm_slot = NULL;
  for (size_t i = 0; i < ASSEMBLER_CACHE_SIZE; i++) {
    frame_assembler_t *a = &tconn->assemblers[i];
    if (a->total_symbols > 0 && a->track_id == track_id &&
        a->group_id == group_id && a->object_id == object_id) {
      asm_slot = a;
      break;
    }
  }

  if (!asm_slot) {
    asm_slot = &tconn->assemblers[tconn->assembler_index];
    tconn->assembler_index =
        (tconn->assembler_index + 1) % ASSEMBLER_CACHE_SIZE;

    if (asm_slot->total_symbols > 0 && !asm_slot->decoded) {
      moq_track_id_t resolved_track;
      if (find_subscription_by_alias(tconn, asm_slot->track_id,
                                     &resolved_track) == 0) {
        transport_event_t ev = {.type = TRANSPORT_EVENT_OBJECT_LOST,
                                .conn = tconn,
                                .track_id = resolved_track,
                                .object = {.track_id = resolved_track,
                                           .group_id = asm_slot->group_id,
                                           .object_id = asm_slot->object_id}};
        tconn->transport->callback(tconn->transport->user_data, &ev);
      }
    }

    if (!asm_slot->buffers || asm_slot->capacity_symbols < total_symbols ||
        asm_slot->capacity_symbol_size < symbol_size) {
      if (asm_slot->buffers) {
        for (size_t i = 0; i < asm_slot->capacity_symbols; i++) {
          free(asm_slot->buffers[i]);
        }
        free(asm_slot->buffers);
        free(asm_slot->received_mask);
        free(asm_slot->missing_indices);
      }

      asm_slot->capacity_symbols = total_symbols > 256 ? total_symbols : 256;
      asm_slot->capacity_symbol_size = symbol_size > 1250 ? symbol_size : 1250;
      asm_slot->buffers = calloc(asm_slot->capacity_symbols, sizeof(uint8_t *));
      asm_slot->received_mask =
          calloc(asm_slot->capacity_symbols, sizeof(bool));
      asm_slot->missing_indices =
          calloc(asm_slot->capacity_symbols, sizeof(uint16_t));
      for (size_t i = 0; i < asm_slot->capacity_symbols; i++) {
        asm_slot->buffers[i] = calloc(1, asm_slot->capacity_symbol_size);
      }
    }

    memset(asm_slot->received_mask, 0,
           asm_slot->capacity_symbols * sizeof(bool));
    asm_slot->track_id = track_id;
    asm_slot->group_id = group_id;
    asm_slot->object_id = object_id;
    asm_slot->total_symbols = total_symbols;
    asm_slot->data_symbols = data_symbols;
    asm_slot->symbol_size = symbol_size;
    asm_slot->original_size = original_size;
    asm_slot->priority = hdr->priority;
    asm_slot->decoded = false;
    asm_slot->received_count = 0;
    asm_slot->nack_sent = false;
  }

  if (asm_slot->decoded)
    return;

  if (symbol_index >= total_symbols)
    return;

  if (!asm_slot->received_mask[symbol_index]) {
    memcpy(asm_slot->buffers[symbol_index],
           payload.base + sizeof(fec_packet_header_t), symbol_size);
    asm_slot->received_mask[symbol_index] = true;
    asm_slot->received_count++;
  }

  if (resolved_track.type == MOQ_TRACK_DATA && !asm_slot->decoded &&
      !asm_slot->nack_sent &&
      asm_slot->received_count >= (asm_slot->data_symbols + 1) / 2) {
    uint16_t missing_count = 0;
    for (uint16_t i = 0; i < asm_slot->total_symbols; i++) {
      if (!asm_slot->received_mask[i]) {
        asm_slot->missing_indices[missing_count++] = i;
      }
    }
    if (missing_count > 0) {
      send_nack(tconn, track_id, group_id, object_id, asm_slot->missing_indices,
                missing_count);
      asm_slot->nack_sent = true;
    }
  }

  if (asm_slot->received_count >= data_symbols) {
    bool got_all_data = true;
    for (size_t i = 0; i < data_symbols; i++) {
      if (!asm_slot->received_mask[i]) {
        got_all_data = false;
        break;
      }
    }

    bool success = false;
    if (got_all_data) {
      success = true;
    } else {
      size_t parity_symbols = total_symbols - data_symbols;
      if (parity_symbols > 0) {
        fec_type_t fec_type =
            (resolved_track.type == MOQ_TRACK_DATA && total_symbols > 255)
                ? FEC_RAPTORQ
                : FEC_REED_SOLOMON;
        fec_t *fec = get_cached_fec(t, fec_type, data_symbols, parity_symbols,
                                    symbol_size);
        if (fec) {
          bool missing[256];
          memset(missing, 0, sizeof(missing));
          for (size_t i = 0; i < total_symbols; i++) {
            missing[i] = !asm_slot->received_mask[i];
          }
          success = fec_decode(fec, asm_slot->buffers, missing);
        }
      }
    }

    if (success) {
      uint8_t *full_data = malloc(original_size);
      size_t bytes_left = original_size;
      for (size_t i = 0; i < data_symbols; i++) {
        size_t chunk = (bytes_left < symbol_size) ? bytes_left : symbol_size;
        if (chunk > 0) {
          memcpy(full_data + (i * symbol_size), asm_slot->buffers[i], chunk);
          bytes_left -= chunk;
        }
      }

      resolved_track.flags |= MOQ_TRACK_FLAG_FEC_ENABLED;
      resolved_track.flags &= ~MOQ_TRACK_FLAG_RELIABLE;
      transport_event_t ev = {.type = TRANSPORT_EVENT_OBJECT,
                              .conn = tconn,
                              .track_id = resolved_track,
                              .object = {.track_id = resolved_track,
                                         .group_id = group_id,
                                         .object_id = object_id,
                                         .data = full_data,
                                         .size = original_size,
                                         .is_keyframe = (is_keyframe != 0),
                                         .priority = asm_slot->priority}};
      t->callback(t->user_data, &ev);
      free(full_data);
      asm_slot->decoded = true;
    }
  }
}

static int load_certificate_and_key(ptls_context_t *tlsctx,
                                    ptls_openssl_sign_certificate_t *sign_cert,
                                    const char *cert_file,
                                    const char *key_file) {
  if (!cert_file || !key_file) {
    fprintf(stderr, "certificate file and key file are required\n");
    return -1;
  }

  if (ptls_load_certificates(tlsctx, (char *)cert_file) != 0) {
    fprintf(stderr, "failed to load certificates\n");
    return -1;
  }

  FILE *fp = fopen(key_file, "r");
  if (!fp) {
    fprintf(stderr, "failed to open private key file\n");
    return -1;
  }
  EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
  fclose(fp);
  if (!pkey) {
    fprintf(stderr, "failed to load private key\n");
    return -1;
  }
  ptls_openssl_init_sign_certificate(sign_cert, pkey);
  EVP_PKEY_free(pkey);
  tlsctx->sign_certificate = &sign_cert->super;
  return 0;
}

typedef struct {
  uint32_t index;
  struct sockaddr_storage addr;
  socklen_t addr_len;
  int is_added;
} ifmon_pipe_msg_t;

static void bind_to_device(int fd, uint32_t index) {
  if (index == 0)
    return;
#if defined(__linux__)
  char ifname[IF_NAMESIZE];
  if (if_indextoname(index, ifname)) {
    if (strncmp(ifname, "veth", 4) == 0)
      return;
    setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname));
  }
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)
#ifndef IP_BOUND_IF
#define IP_BOUND_IF 25
#endif
#ifndef IPV6_BOUND_IF
#define IPV6_BOUND_IF 125
#endif
  unsigned int idx = index;
  setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &idx, sizeof(idx));
  setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &idx, sizeof(idx));
#elif defined(_WIN32)
  DWORD idx = index;
  setsockopt(fd, IPPROTO_IP, IP_UNICAST_IF, (const char *)&idx, sizeof(idx));
  setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_IF, (const char *)&idx,
             sizeof(idx));
#endif
}

static void on_ifmon_update(const ifmon_update_t *update, void *userdata) {
  transport_t *t = userdata;

  if (update->is_initial) {
    /* For now, ignore initial snapshot since we bind via config->bind_hosts */
    return;
  }

  for (int i = 0; i < update->added_count; i++) {
    uint32_t idx = update->added[i];
    for (int j = 0; j < update->interfaces->count; j++) {
      if (update->interfaces->ifaces[j].index == idx) {
        const ifmon_iface_t *iface = &update->interfaces->ifaces[j];
        for (int k = 0; k < iface->addr_count; k++) {
          const ifmon_addr_t *a = &iface->addrs[k];
          ifmon_pipe_msg_t msg = {0};
          msg.index = idx;
          msg.is_added = 1;
          if (a->family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)&msg.addr;
            sin->sin_family = AF_INET;
            sin->sin_addr = a->ip.v4;
            msg.addr_len = sizeof(*sin);
          } else {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&msg.addr;
            sin6->sin6_family = AF_INET6;
            sin6->sin6_addr = a->ip.v6;
            msg.addr_len = sizeof(*sin6);
          }
          ssize_t w = write(t->ifmon_pipe[1], &msg, sizeof(msg));
          (void)w;
        }
        break;
      }
    }
  }

  for (int i = 0; i < update->modified_count; i++) {
    const ifmon_iface_diff_t *diff = &update->modified[i];
    for (int j = 0; j < diff->addrs_added_count; j++) {
      const ifmon_addr_t *a = &diff->addrs_added[j];
      ifmon_pipe_msg_t msg = {0};
      msg.index = diff->index;
      msg.is_added = 1;
      if (a->family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&msg.addr;
        sin->sin_family = AF_INET;
        sin->sin_addr = a->ip.v4;
        msg.addr_len = sizeof(*sin);
      } else {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&msg.addr;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_addr = a->ip.v6;
        msg.addr_len = sizeof(*sin6);
      }
      ssize_t w = write(t->ifmon_pipe[1], &msg, sizeof(msg));
      (void)w;
    }

    for (int j = 0; j < diff->addrs_removed_count; j++) {
      const ifmon_addr_t *a = &diff->addrs_removed[j];
      ifmon_pipe_msg_t msg = {0};
      msg.index = diff->index;
      msg.is_added = 0;
      if (a->family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&msg.addr;
        sin->sin_family = AF_INET;
        sin->sin_addr = a->ip.v4;
        msg.addr_len = sizeof(*sin);
      } else {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&msg.addr;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_addr = a->ip.v6;
        msg.addr_len = sizeof(*sin6);
      }
      ssize_t w = write(t->ifmon_pipe[1], &msg, sizeof(msg));
      (void)w;
    }
  }
}

transport_t *transport_create(const transport_config_t *config) {
  transport_t *t = calloc(1, sizeof(transport_t));
  if (!t)
    return NULL;

  t->arena.capacity = 16 * 1024 * 1024;
  t->arena.buffer = malloc(t->arena.capacity);
  t->arena.offset = 0;
  t->arena.fallback_count = 0;
  if (!t->arena.buffer) {
    free(t);
    return NULL;
  }

  t->callback = config->callback;
  t->user_data = config->user_data;
  t->is_server = (config->num_remote_hosts == 0);
  t->simulated_loss_rate = config->simulated_loss_rate;

  t->last_pathflow_update = ptls_get_time.cb(&ptls_get_time);

  if (pipe(t->ifmon_pipe) == 0) {
    fcntl(t->ifmon_pipe[0], F_SETFL,
          fcntl(t->ifmon_pipe[0], F_GETFL) | O_NONBLOCK);
    fcntl(t->ifmon_pipe[1], F_SETFL,
          fcntl(t->ifmon_pipe[1], F_GETFL) | O_NONBLOCK);
    ifmon_watch_start(&t->ifmon_w, on_ifmon_update, t);
  } else {
    t->ifmon_pipe[0] = -1;
    t->ifmon_pipe[1] = -1;
  }

  /* setup cryptographic context */
  t->tls_ctx.random_bytes = ptls_openssl_random_bytes;
  t->tls_ctx.get_time = &ptls_get_time;
  t->tls_ctx.key_exchanges = ptls_openssl_key_exchanges;
  t->tls_ctx.cipher_suites = ptls_openssl_cipher_suites;

  t->stream_open.cb = on_stream_open;
  t->receive_datagram.cb = on_receive_datagram_frame;
  t->verifier_initialized = false;

  t->quic_ctx = quicly_spec_context;

  /* Setup CID encryptor to support active connection migration */
  static char cid_key[16];
  ptls_openssl_random_bytes(cid_key, sizeof(cid_key));
  t->quic_ctx.cid_encryptor = quicly_new_default_cid_encryptor(
      &ptls_openssl_quiclb, &ptls_openssl_aes128ecb, &ptls_openssl_sha256,
      ptls_iovec_init(cid_key, sizeof(cid_key)));

  t->quic_ctx.tls = &t->tls_ctx;
  quicly_amend_ptls_context(t->quic_ctx.tls);
  t->quic_ctx.stream_open = &t->stream_open;
  t->quic_ctx.receive_datagram_frame = &t->receive_datagram;

  t->quic_ctx.path_scheduler = &quicly_round_robin_path_scheduler;

  t->quic_ctx.initcwnd_packets = 100;
  t->quic_ctx.transport_params.max_datagram_frame_size = 1500;
  t->quic_ctx.transport_params.max_streams_uni = 100;
  t->quic_ctx.transport_params.max_streams_bidi = 100;

  t->quic_ctx.transport_params.active_connection_id_limit = 8;
  t->quic_ctx.transport_params.initial_max_path_id = TRANSPORT_MAX_PATHS;

  t->num_fds = config->num_bind_hosts;
  t->num_remote_addrs = config->num_remote_hosts;

  for (size_t i = 0; i < t->num_fds; i++) {
    if (strchr(config->bind_hosts[i], ':')) {
      struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&t->local_addrs[i];
      sin6->sin6_family = AF_INET6;
      inet_pton(AF_INET6, config->bind_hosts[i], &sin6->sin6_addr);
      sin6->sin6_port = t->is_server ? htons(config->port) : 0;
      t->local_addrs_len[i] = sizeof(struct sockaddr_in6);
      t->fds[i] = socket(AF_INET6, SOCK_DGRAM, 0);
    } else {
      struct sockaddr_in *sin = (struct sockaddr_in *)&t->local_addrs[i];
      sin->sin_family = AF_INET;
      inet_pton(AF_INET, config->bind_hosts[i], &sin->sin_addr);
      sin->sin_port = t->is_server ? htons(config->port) : 0;
      t->local_addrs_len[i] = sizeof(struct sockaddr_in);
      t->fds[i] = socket(AF_INET, SOCK_DGRAM, 0);
    }
    if (t->fds[i] < 0)
      return NULL;

    int reuse = 1;
    setsockopt(t->fds[i], SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    if (bind(t->fds[i], (struct sockaddr *)&t->local_addrs[i],
             t->local_addrs_len[i]) != 0)
      return NULL;

    int flags = fcntl(t->fds[i], F_GETFL, 0);
    fcntl(t->fds[i], F_SETFL, flags | O_NONBLOCK);
  }

  if (t->is_server || (config->cert_file && config->key_file)) {
    if (load_certificate_and_key(&t->tls_ctx, &t->sign_cert, config->cert_file,
                                 config->key_file) != 0)
      return NULL;
  }

  if (config->verify_peer) {
    X509_STORE *store = NULL;
    if (config->ca_file) {
      store = X509_STORE_new();
      if (X509_STORE_load_locations(store, config->ca_file, NULL) != 1) {
        fprintf(stderr, "failed to load CA certificates from %s\n",
                config->ca_file);
        X509_STORE_free(store);
        return NULL;
      }
    }

    /* ptls_openssl_init_verify_certificate will take its own reference to store
     * (if provided), or load the system default certificates if store is NULL
     */
    if (ptls_openssl_init_verify_certificate(&t->verifier, store) != 0) {
      fprintf(stderr, "failed to initialize certificate verifier\n");
      if (store) {
        X509_STORE_free(store);
      }
      return NULL;
    }
    if (store) {
      X509_STORE_free(store); /* drop our local reference */
    }

    t->tls_ctx.verify_certificate = &t->verifier.super;
    t->verifier_initialized = true;

    if (t->is_server) {
      t->tls_ctx.require_client_authentication = 1;
    }
  } else {
    t->verifier.super.cb = verify_certificate_cb;
    t->verifier.super.algos = verify_algos;
    t->tls_ctx.verify_certificate = &t->verifier.super;
    t->verifier_initialized = false;
  }

  if (!t->is_server) {
    for (size_t i = 0; i < t->num_remote_addrs; i++) {
      if (strchr(config->remote_hosts[i], ':')) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&t->remote_addrs[i];
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(config->port);
        inet_pton(AF_INET6, config->remote_hosts[i], &sin6->sin6_addr);
        t->remote_addrs_len[i] = sizeof(struct sockaddr_in6);
      } else {
        struct sockaddr_in *sin = (struct sockaddr_in *)&t->remote_addrs[i];
        sin->sin_family = AF_INET;
        sin->sin_port = htons(config->port);
        inet_pton(AF_INET, config->remote_hosts[i], &sin->sin_addr);
        t->remote_addrs_len[i] = sizeof(struct sockaddr_in);
      }
    }

    transport_conn_t *conn = calloc(1, sizeof(transport_conn_t));
    conn->transport = t;

    int ret =
        quicly_connect(&conn->quic, &t->quic_ctx, config->remote_hosts[0],
                       (struct sockaddr *)&t->remote_addrs[0],
                       (struct sockaddr *)&t->local_addrs[0], &t->next_cid,
                       ptls_iovec_init(NULL, 0), NULL, NULL, NULL);
    if (ret != 0)
      return NULL;

    *quicly_get_data(conn->quic) = conn;
    t->client_conn = conn;

    quicly_open_stream(conn->quic, &conn->stream, 0);
  }

  /* make socket nonblocking is handled in the loop */
  return t;
}

void transport_destroy(transport_t *t) {
  if (!t)
    return;

  if (t->ifmon_pipe[0] >= 0) {
    ifmon_watch_stop(&t->ifmon_w);
  }
  if (t->ifmon_pipe[0] >= 0) {
    CLOSE_SOCKET(t->ifmon_pipe[0]);
    CLOSE_SOCKET(t->ifmon_pipe[1]);
  }

  for (size_t i = 0; i < t->num_fds; i++) {
    if (t->fds[i] >= 0) {
      CLOSE_SOCKET(t->fds[i]);
    }
  }

  if (t->is_server) {
    for (size_t i = 0; i < t->conn_count; i++) {
      transport_conn_t *conn = t->conns[i];
      quicly_free(conn->quic);
      for (size_t a = 0; a < ASSEMBLER_CACHE_SIZE; a++) {
        if (conn->assemblers[a].buffers) {
          for (size_t s = 0; s < conn->assemblers[a].capacity_symbols; s++) {
            free(conn->assemblers[a].buffers[s]);
          }
          free(conn->assemblers[a].buffers);
          free(conn->assemblers[a].received_mask);
          free(conn->assemblers[a].missing_indices);
        }
      }
      free(conn);
    }
  } else if (t->client_conn) {
    transport_conn_t *conn = t->client_conn;
    quicly_free(conn->quic);
    for (size_t a = 0; a < ASSEMBLER_CACHE_SIZE; a++) {
      if (conn->assemblers[a].buffers) {
        for (size_t s = 0; s < conn->assemblers[a].capacity_symbols; s++) {
          free(conn->assemblers[a].buffers[s]);
        }
        free(conn->assemblers[a].buffers);
        free(conn->assemblers[a].received_mask);
        free(conn->assemblers[a].missing_indices);
      }
    }
    free(conn);
  }

  for (size_t i = 0; i < SENT_CACHE_SIZE; i++) {
    if (t->sent_cache[i].data) {
      free(t->sent_cache[i].data);
    }
  }

  for (size_t i = 0; i < FEC_CACHE_SIZE; i++) {
    if (t->fec_cache[i].fec) {
      fec_destroy(t->fec_cache[i].fec);
    }
  }

  if (t->arena.buffer) {
    free(t->arena.buffer);
  }
  for (size_t i = 0; i < t->arena.fallback_count; i++) {
    free(t->arena.fallbacks[i]);
  }

  if (t->quic_ctx.cid_encryptor != NULL) {
    quicly_free_default_cid_encryptor(t->quic_ctx.cid_encryptor);
  }

  if (t->fec_buf) {
    free(t->fec_buf);
  }

  if (t->verifier_initialized) {
    ptls_openssl_dispose_verify_certificate(&t->verifier);
  }

  free(t);
}

static void flush_fec_buffer(transport_t *t);

void transport_tick(transport_t *t) {
  if (!t)
    return;

  /* Check for FEC grouping buffer timeout (3 milliseconds) */
  if (t->fec_buf_len > 0) {
    uint64_t now = ptls_get_time.cb(&ptls_get_time);
    if ((now - t->fec_first_pkt_time) >= 3) {
      flush_fec_buffer(t);
    }
  }

  /* process ifmon events */
  if (t->ifmon_pipe[0] >= 0) {
    ifmon_pipe_msg_t msg;
    while (read(t->ifmon_pipe[0], &msg, sizeof(msg)) == sizeof(msg)) {
      if (msg.is_added) {
        if (t->num_fds < TRANSPORT_MAX_PATHS) {
          /* Check if the new IP address matches the client/server side of the
           * initially bound IP address */
          if (msg.addr.ss_family == AF_INET &&
              t->local_addrs[0].ss_family == AF_INET) {
            uint32_t bound_ip = ntohl(
                ((struct sockaddr_in *)&t->local_addrs[0])->sin_addr.s_addr);
            uint32_t new_ip =
                ntohl(((struct sockaddr_in *)&msg.addr)->sin_addr.s_addr);
            if ((bound_ip & 0xFF) != (new_ip & 0xFF)) {
              continue;
            }
          }
          int fd = socket(msg.addr.ss_family, SOCK_DGRAM, 0);
          if (fd >= 0) {
            int reuse = 1;
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
            if (msg.addr.ss_family == AF_INET) {
              ((struct sockaddr_in *)&msg.addr)->sin_port =
                  t->is_server
                      ? (t->local_addrs[0].ss_family == AF_INET
                             ? ((struct sockaddr_in *)&t->local_addrs[0])
                                   ->sin_port
                             : ((struct sockaddr_in6 *)&t->local_addrs[0])
                                   ->sin6_port)
                      : 0;
            } else {
              ((struct sockaddr_in6 *)&msg.addr)->sin6_port =
                  t->is_server
                      ? (t->local_addrs[0].ss_family == AF_INET
                             ? ((struct sockaddr_in *)&t->local_addrs[0])
                                   ->sin_port
                             : ((struct sockaddr_in6 *)&t->local_addrs[0])
                                   ->sin6_port)
                      : 0;
            }

            if (bind(fd, (struct sockaddr *)&msg.addr, msg.addr_len) == 0) {
              int flags = fcntl(fd, F_GETFL, 0);
              fcntl(fd, F_SETFL, flags | O_NONBLOCK);
              bind_to_device(fd, msg.index);

              t->fds[t->num_fds] = fd;
              t->local_addrs[t->num_fds] = msg.addr;
              t->local_addrs_len[t->num_fds] = msg.addr_len;
              t->num_fds++;

              char ip_str[64];
              if (msg.addr.ss_family == AF_INET) {
                inet_ntop(AF_INET, &((struct sockaddr_in *)&msg.addr)->sin_addr,
                          ip_str, sizeof(ip_str));
              } else {
                inet_ntop(AF_INET6,
                          &((struct sockaddr_in6 *)&msg.addr)->sin6_addr,
                          ip_str, sizeof(ip_str));
              }
              fprintf(stderr, "ifmon: opened new socket for local IP %s\n",
                      ip_str);

              if (!t->is_server && t->client_conn) {
                for (size_t r = 0; r < t->num_remote_addrs; r++) {
                  /* Only open path if the local and remote addresses are on the
                   * same /24 subnet */
                  if (t->remote_addrs[r].ss_family == AF_INET &&
                      msg.addr.ss_family == AF_INET) {
                    uint32_t remote_ip =
                        ntohl(((struct sockaddr_in *)&t->remote_addrs[r])
                                  ->sin_addr.s_addr);
                    uint32_t local_ip = ntohl(
                        ((struct sockaddr_in *)&msg.addr)->sin_addr.s_addr);
                    if ((remote_ip & 0xFFFFFF00) != (local_ip & 0xFFFFFF00)) {
                      continue;
                    }
                  }
                  quicly_open_path(t->client_conn->quic,
                                   (struct sockaddr *)&t->remote_addrs[r],
                                   (struct sockaddr *)&msg.addr);
                }
              }
            } else {
              CLOSE_SOCKET(fd);
            }
          }
        }
      } else {
        /* ip removed */
        for (size_t i = 0; i < t->num_fds; i++) {
          if (t->local_addrs[i].ss_family == msg.addr.ss_family) {
            int match = 0;
            if (msg.addr.ss_family == AF_INET) {
              struct sockaddr_in *s1 = (struct sockaddr_in *)&t->local_addrs[i];
              struct sockaddr_in *s2 = (struct sockaddr_in *)&msg.addr;
              if (s1->sin_addr.s_addr == s2->sin_addr.s_addr)
                match = 1;
            } else {
              struct sockaddr_in6 *s1 =
                  (struct sockaddr_in6 *)&t->local_addrs[i];
              struct sockaddr_in6 *s2 = (struct sockaddr_in6 *)&msg.addr;
              if (memcmp(&s1->sin6_addr, &s2->sin6_addr,
                         sizeof(struct in6_addr)) == 0)
                match = 1;
            }
            if (match) {
              CLOSE_SOCKET(t->fds[i]);
              /* remove from array */
              for (size_t j = i; j < t->num_fds - 1; j++) {
                t->fds[j] = t->fds[j + 1];
                t->local_addrs[j] = t->local_addrs[j + 1];
                t->local_addrs_len[j] = t->local_addrs_len[j + 1];
              }
              t->num_fds--;
              fprintf(stderr, "ifmon: removed socket for local IP\n");
              break;
            }
          }
        }
      }
    }
  }

  for (size_t fd_idx = 0; fd_idx < t->num_fds; fd_idx++) {
    while (1) {
      uint8_t buf[2048];
      struct sockaddr_storage sa;
      socklen_t sa_len = sizeof(sa);
      ssize_t rret = recvfrom(t->fds[fd_idx], buf, sizeof(buf), 0,
                              (struct sockaddr *)&sa, &sa_len);
      if (rret == -1) {
        if (SOCKET_ERROR_CODE == SOCKET_EAGAIN ||
            SOCKET_ERROR_CODE == SOCKET_EWOULDBLOCK)
          break;
        continue;
      }

      struct sockaddr *psa = (struct sockaddr *)&sa;

      quicly_decoded_packet_t decoded;
      size_t off = 0;
      while (off < (size_t)rret) {
        if (quicly_decode_packet(&t->quic_ctx, &decoded, buf, rret, &off) ==
            SIZE_MAX)
          break;

        transport_conn_t *target = NULL;
        if (t->is_server) {
          for (size_t i = 0; i < t->conn_count; ++i) {
            if (quicly_is_destination(
                    t->conns[i]->quic,
                    (struct sockaddr *)&t->local_addrs[fd_idx], psa,
                    &decoded)) {
              target = t->conns[i];
              break;
            }
          }
          if (!target && t->conn_count < MAX_CONNECTIONS) {
            quicly_conn_t *new_quic = NULL;
            int accept_res =
                quicly_accept(&new_quic, &t->quic_ctx,
                              (struct sockaddr *)&t->local_addrs[fd_idx], psa,
                              &decoded, NULL, &t->next_cid, NULL, NULL);
            if (accept_res == 0 && new_quic) {
              target = calloc(1, sizeof(transport_conn_t));
              target->transport = t;
              target->quic = new_quic;
              *quicly_get_data(new_quic) = target;
              t->conns[t->conn_count++] = target;
            }
          }
        } else {
          target = t->client_conn;
        }

        if (target) {
          quicly_receive(target->quic,
                         (struct sockaddr *)&t->local_addrs[fd_idx], psa,
                         &decoded);
        }
      }
    }
  }

  /* run tick timeout for active connections and check sends */
  uint64_t now = ptls_get_time.cb(&ptls_get_time);

  if (now - t->last_pathflow_update >= 25) {
    t->last_pathflow_update = now;

    transport_conn_t *target = t->is_server
                                   ? (t->conn_count > 0 ? t->conns[0] : NULL)
                                   : t->client_conn;
    if (target) {
      quicly_stats_t stats;
      if (quicly_get_stats(target->quic, &stats) == 0) {
        size_t symbol_size = 1100;
        if (t->quic_ctx.initial_egress_max_udp_payload_size > 80) {
          symbol_size = t->quic_ctx.initial_egress_max_udp_payload_size - 80;
        }
        if (symbol_size < 1000)
          symbol_size = 1000;

        /* convert RTT to seconds */
        fp_t l = FP_DIV(FP_FROM_INT(stats.rtt.smoothed), FP_FROM_INT(1000));

        /* convert bandwidth to packets/second */
        size_t cwnd_packets = stats.cc.cwnd / symbol_size;
        if (cwnd_packets == 0)
          cwnd_packets = 1;
        uint32_t rtt_val = stats.rtt.smoothed > 0 ? stats.rtt.smoothed : 1;
        fp_t b = FP_FROM_INT(cwnd_packets * 1000 / rtt_val);
        if (b <= 0) {
          b = FP_FROM_INT(100);
        }

        fp_t p = FP_FROM_FLOAT(0.01f); /* default mock loss rate */
        size_t q = 0; /* bytes in flight or egress queue size */

        for (size_t i = 0; i < t->num_fds; i++) {
          /* use path-specific stats if available, otherwise fallback to
           * connection defaults */
          fp_t path_l = l / 2;
          fp_t path_p = p;
          quicly_path_stats_t path_stats;

          size_t path_idx = find_path_index_by_link(target->quic, t, i);
          if (quicly_get_path_stats(target->quic, path_idx, &path_stats) == 0) {
            if (path_stats.rtt_smoothed > 0) {
              path_l = FP_DIV(FP_FROM_INT(path_stats.rtt_smoothed),
                              FP_FROM_INT(2000));
            }
            if (path_stats.sent > 0) {
              path_p = FP_DIV(FP_FROM_INT(path_stats.lost),
                              FP_FROM_INT(path_stats.sent));
            }
          }

          if (t->latest_owd_fp[i] > 0) {
            path_l += t->latest_owd_fp[i];
          }

          pathflow_update_state(&t->path_states[i], b, path_l, path_p, q,
                                FP_FROM_FLOAT(0.1f));
        }
      }
    }
  }

  size_t active_count = t->is_server ? t->conn_count : (t->client_conn ? 1 : 0);
  for (size_t i = 0; i < active_count; ++i) {
    transport_conn_t *conn = t->is_server ? t->conns[i] : t->client_conn;
    if (!conn)
      continue;

    /* check and raise connected event once handshake is ready */
    if (!conn->handshake_complete && quicly_connection_is_ready(conn->quic)) {
      conn->handshake_complete = true;
      transport_event_t ev = {.type = TRANSPORT_EVENT_CONNECTED, .conn = conn};
      t->callback(t->user_data, &ev);
    }

    while (1) {
      quicly_address_t dest, src;
      struct iovec dgrams[64];
      uint8_t dgrams_buf[64 * 1500];
      size_t num_dgrams = 64;
      int send_res = quicly_send(conn->quic, &dest, &src, dgrams, &num_dgrams,
                                 dgrams_buf, sizeof(dgrams_buf));
      if (send_res == 0) {
        if (num_dgrams == 0)
          break;

        for (size_t j = 0; j < num_dgrams; ++j) {
          struct msghdr mess = {.msg_name = &dest.sa,
                                .msg_namelen = quicly_get_socklen(&dest.sa),
                                .msg_iov = &dgrams[j],
                                .msg_iovlen = 1};
          int out_fd = t->fds[0];
          if (src.sa.sa_family == AF_INET) {
            struct sockaddr_in *src_in = (struct sockaddr_in *)&src.sa;
            for (size_t k = 0; k < t->num_fds; k++) {
              if (t->local_addrs[k].ss_family == AF_INET) {
                struct sockaddr_in *loc =
                    (struct sockaddr_in *)&t->local_addrs[k];
                if (loc->sin_addr.s_addr == src_in->sin_addr.s_addr) {
                  out_fd = t->fds[k];
                  break;
                }
              }
            }
          } else if (src.sa.sa_family == AF_INET6) {
            struct sockaddr_in6 *src_in6 = (struct sockaddr_in6 *)&src.sa;
            for (size_t k = 0; k < t->num_fds; k++) {
              if (t->local_addrs[k].ss_family == AF_INET6) {
                struct sockaddr_in6 *loc =
                    (struct sockaddr_in6 *)&t->local_addrs[k];
                if (memcmp(&loc->sin6_addr, &src_in6->sin6_addr,
                           sizeof(struct in6_addr)) == 0) {
                  out_fd = t->fds[k];
                  break;
                }
              }
            }
          }

          ssize_t sret;
          while ((sret = sendto(out_fd, dgrams[j].iov_base, dgrams[j].iov_len,
                                0, mess.msg_name, mess.msg_namelen)) == -1 &&
                 SOCKET_ERROR_CODE == SOCKET_EINTR)
            ;
          if (sret == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
            fprintf(stderr, "sendmsg failed: %s (errno=%d)\n", strerror(errno),
                    errno);
          }
        }
      } else if (send_res == QUICLY_ERROR_FREE_CONNECTION) {
        fprintf(stderr, "Connection %p freed (is_server=%d)\n", conn,
                t->is_server);
        transport_event_t ev = {.type = TRANSPORT_EVENT_DISCONNECTED,
                                .conn = conn};
        t->callback(t->user_data, &ev);

        quicly_free(conn->quic);
        for (size_t a = 0; a < ASSEMBLER_CACHE_SIZE; a++) {
          if (conn->assemblers[a].buffers) {
            for (size_t s = 0; s < conn->assemblers[a].capacity_symbols; s++) {
              free(conn->assemblers[a].buffers[s]);
            }
            free(conn->assemblers[a].buffers);
            free(conn->assemblers[a].received_mask);
            free(conn->assemblers[a].missing_indices);
          }
        }
        free(conn);

        if (t->is_server) {
          memmove(t->conns + i, t->conns + i + 1,
                  sizeof(t->conns[0]) * (t->conn_count - i - 1));
          t->conn_count--;
          i--;
          active_count = t->conn_count;
        } else {
          t->client_conn = NULL;
          active_count = 0;
        }
        break;
      } else {
        break;
      }
    }
  }
}

typedef struct {
  bool reliable;
  bool fec_enabled;
} track_delivery_profile_t;

/* get delivery profile based on track type and name */
static track_delivery_profile_t get_track_profile(const moq_track_id_t *track) {
  track_delivery_profile_t profile = {
      .reliable = (track->flags & MOQ_TRACK_FLAG_RELIABLE) != 0,
      .fec_enabled = (track->flags & MOQ_TRACK_FLAG_FEC_ENABLED) != 0};
  return profile;
}

static void flush_fec_buffer(transport_t *t) {
  if (t->fec_buf_len == 0)
    return;

  moq_object_t obj = {.track_id = t->fec_track_id,
                      .group_id = 0,
                      .object_id = t->fec_object_id++,
                      .data = t->fec_buf,
                      .size = t->fec_buf_len,
                      .is_keyframe = false,
                      .priority = t->fec_priority};

  t->fec_in_flush = true;
  transport_publish(t, &obj);
  t->fec_in_flush = false;

  t->fec_buf_len = 0;
  t->fec_first_pkt_time = 0;
  t->fec_pkt_count = 0;
}

bool transport_publish(transport_t *t, const moq_object_t *obj) {
  if (!t)
    return false;

  /* route to grouping buffer if it's data and we're not flushing */
  if (obj->track_id.type == MOQ_TRACK_DATA && !t->fec_in_flush) {
    bool use_fec = false;
    if (t->is_server) {
      for (size_t c = 0; c < t->conn_count; c++) {
        transport_conn_t *conn = t->conns[c];
        if (conn && conn->quic &&
            quicly_get_state(conn->quic) < QUICLY_STATE_CLOSING) {
          for (int s = 0; s < 32; s++) {
            if (conn->subscriptions[s].active &&
                conn->subscriptions[s].track_id.type == obj->track_id.type &&
                strcmp(conn->subscriptions[s].track_id.name,
                       obj->track_id.name) == 0) {
              track_delivery_profile_t profile =
                  get_track_profile(&conn->subscriptions[s].track_id);
              if (profile.fec_enabled) {
                use_fec = true;
                break;
              }
            }
          }
          if (use_fec)
            break;
        }
      }
    } else if (t->client_conn) {
      transport_conn_t *conn = t->client_conn;
      for (int s = 0; s < 32; s++) {
        if (conn->subscriptions[s].active &&
            conn->subscriptions[s].track_id.type == obj->track_id.type &&
            strcmp(conn->subscriptions[s].track_id.name, obj->track_id.name) ==
                0) {
          track_delivery_profile_t profile =
              get_track_profile(&conn->subscriptions[s].track_id);
          if (profile.fec_enabled) {
            use_fec = true;
            break;
          }
        }
      }
    }

    if (use_fec) {
      uint64_t now = ptls_get_time.cb(&ptls_get_time);
      if (t->fec_buf_len == 0) {
        t->fec_first_pkt_time = now;
        t->fec_track_id = obj->track_id;
        t->fec_priority = obj->priority;
      }

      size_t needed = t->fec_buf_len + 2 + obj->size;
      if (needed > t->fec_buf_cap) {
        size_t new_cap = t->fec_buf_cap == 0 ? 4096 : t->fec_buf_cap * 2;
        while (new_cap < needed)
          new_cap *= 2;
        uint8_t *new_buf = realloc(t->fec_buf, new_cap);
        if (!new_buf) {
          return false;
        }
        t->fec_buf = new_buf;
        t->fec_buf_cap = new_cap;
      }

      uint16_t len_be = htons((uint16_t)obj->size);
      memcpy(t->fec_buf + t->fec_buf_len, &len_be, 2);
      memcpy(t->fec_buf + t->fec_buf_len + 2, obj->data, obj->size);
      t->fec_buf_len = needed;
      t->fec_pkt_count++;

      if (t->fec_pkt_count >= 4 || t->fec_buf_len >= 4000) {
        flush_fec_buffer(t);
      }
      return true;
    }
  }

  track_delivery_profile_t profile = get_track_profile(&obj->track_id);

  /* route over reliable stream if requested by profile */
  if (profile.reliable) {
    size_t active_count =
        t->is_server ? t->conn_count : (t->client_conn ? 1 : 0);
    for (size_t i = 0; i < active_count; ++i) {
      transport_conn_t *conn = t->is_server ? t->conns[i] : t->client_conn;
      if (!conn || !conn->quic ||
          quicly_get_state(conn->quic) >= QUICLY_STATE_CLOSING)
        continue;
      if (t->is_server && !is_subscribed(conn, &obj->track_id))
        continue;

      int sub_idx = -1;
      for (int s = 0; s < 32; s++) {
        if (conn->subscriptions[s].active &&
            conn->subscriptions[s].track_id.type == obj->track_id.type &&
            strcmp(conn->subscriptions[s].track_id.name, obj->track_id.name) ==
                0) {
          sub_idx = s;
          break;
        }
      }

      if (sub_idx >= 0) {
        track_subscription_t *sub = &conn->subscriptions[sub_idx];
        if (!sub->stream ||
            !quicly_sendstate_is_open(&sub->stream->sendstate)) {
          sub->stream = NULL;
          int err = quicly_open_stream(conn->quic, &sub->stream,
                                       1); /* 1 = unidirectional */
          if (err == 0 && sub->stream) {
            quicly_debug_printf(conn->quic,
                                "Opened QUIC Stream %" PRIu64
                                " for MoQ track alias %d",
                                sub->stream->stream_id, sub->alias);
            uint8_t alias = sub->alias;
            quicly_streambuf_egress_write(sub->stream, &alias, 1);
          } else {
            fprintf(stderr, "Failed to open reliable track stream: %d\n", err);
            continue;
          }
        }

        uint32_t sz = htobe32((uint32_t)obj->size);
        quicly_streambuf_egress_write(sub->stream, &sz, sizeof(sz));
        quicly_streambuf_egress_write(sub->stream, obj->data, obj->size);
      } else {
        transport_send_unicast(t, conn, obj->data, obj->size);
      }
    }
    return true;
  }

  /* audio, video, text tracks go over unreliable datagram frames with FEC */
  size_t data_size = obj->size;
  size_t symbol_size = 1100;
  if (t->quic_ctx.initial_egress_max_udp_payload_size > 80) {
    symbol_size = t->quic_ctx.initial_egress_max_udp_payload_size - 80;
  }
  if (symbol_size < 1000)
    symbol_size = 1000;
  size_t data_symbols = (data_size + symbol_size - 1) / symbol_size;
  if (data_symbols == 0)
    data_symbols = 1;

  /* dynamic FEC parity overhead based on priority and track mode */
  fec_type_t fec_type = FEC_REED_SOLOMON;
  size_t parity_symbols = 0;

  path_t paths_array[TRANSPORT_MAX_PATHS];
  memset(paths_array, 0, sizeof(paths_array));

  if (!profile.fec_enabled) {
    parity_symbols = 0;
    for (size_t s = 0; s < data_symbols; s++) {
      size_t path_idx = 0;
      if (t->num_fds > 0) {
        path_idx = s % t->num_fds;
      }
      paths_array[path_idx].x++;
    }
  } else if (data_symbols > 1) {
    if (obj->track_id.type == MOQ_TRACK_DATA) {
      fec_type = FEC_RAPTORQ;
    } else {
      fec_type = FEC_REED_SOLOMON;
    }

    fp_t default_b = FP_FROM_INT(100);      /* 100 pkt/s fallback */
    fp_t default_l = FP_FROM_FLOAT(0.050f); /* 50ms */
    transport_conn_t *target = t->is_server
                                   ? (t->conn_count > 0 ? t->conns[0] : NULL)
                                   : t->client_conn;
    if (target) {
      quicly_stats_t stats;
      if (quicly_get_stats(target->quic, &stats) == 0) {
        if (stats.rtt.smoothed > 0) {
          default_l =
              FP_DIV(FP_FROM_INT(stats.rtt.smoothed), FP_FROM_INT(1000));
        }
        size_t cwnd_packets = stats.cc.cwnd / symbol_size;
        if (cwnd_packets == 0)
          cwnd_packets = 1;
        uint32_t rtt = stats.rtt.smoothed > 0 ? stats.rtt.smoothed : 1;
        default_b = FP_FROM_INT(cwnd_packets * 1000 / rtt);
        if (default_b <= 0) {
          default_b = FP_FROM_INT(100);
        }
      }
    }

    for (size_t i = 0; i < t->num_fds; i++) {
      paths_array[i].b =
          t->path_states[i].b_ewma > 0 ? t->path_states[i].b_ewma : default_b;
      paths_array[i].l =
          t->path_states[i].l_ewma > 0 ? t->path_states[i].l_ewma : default_l;
      paths_array[i].p = t->path_states[i].p_ewma;
      paths_array[i].q = t->path_states[i].q_ewma;
      paths_array[i].m = 0;
      paths_array[i].x = 0;
      paths_array[i].t = 0;
    }

    size_t target_reliability = 95;
    if (obj->priority == 0) {
      target_reliability = 85;
    } else if (obj->priority == 2) {
      target_reliability = 99;
    }

    pathflow_optimize(t->num_fds, data_symbols, paths_array,
                      FP_FROM_FLOAT(10.0f), target_reliability,
                      PATHFLOW_SOLVER_GREEDY);

    /* Force 60/20/15/5 split for testing when 4 paths are available
    {
      size_t total_alloc = 0;
      for (size_t i = 0; i < t->num_fds; i++) {
        total_alloc += paths_array[i].x;
      }
      if (total_alloc > 0 && t->num_fds == 4) {
        paths_array[0].x = (total_alloc * 60 + 50) / 100;
        paths_array[1].x = (total_alloc * 20 + 50) / 100;
        paths_array[2].x = (total_alloc * 15 + 50) / 100;
        paths_array[3].x = (total_alloc * 5 + 50) / 100;

        size_t sum = paths_array[0].x + paths_array[1].x + paths_array[2].x +
                     paths_array[3].x;
        if (sum < total_alloc) {
          paths_array[0].x += (total_alloc - sum);
        } else if (sum > total_alloc) {
          size_t diff = sum - total_alloc;
          if (paths_array[0].x >= diff) {
            paths_array[0].x -= diff;
          } else {
            paths_array[0].x = 0;
          }
        }
      }
    }
    */

    parity_symbols = 0;
    for (size_t i = 0; i < t->num_fds; i++) {
      if (paths_array[i].x > paths_array[i].m) {
        parity_symbols += (paths_array[i].x - paths_array[i].m);
      }
    }
    if (parity_symbols == 0) {
      parity_symbols = 1;
    }
  } else {
    /* For single-symbol frames, distribute them round-robin across active paths
     */
    static size_t rr_path = 0;
    size_t path_idx = 0;
    if (t->num_fds > 0) {
      path_idx = rr_path % t->num_fds;
    }
    paths_array[path_idx].x = 1;
    parity_symbols = 0;
    rr_path++;
  }

  uint8_t **data_blocks =
      arena_alloc(&t->arena, data_symbols * sizeof(uint8_t *));
  uint8_t **parity_blocks =
      arena_alloc(&t->arena, parity_symbols * sizeof(uint8_t *));

  for (size_t i = 0; i < data_symbols; i++) {
    size_t offset = i * symbol_size;
    size_t chunk = (offset < data_size) ? (data_size - offset) : 0;
    if (chunk >= symbol_size) {
      /* Zero-copy reference directly to the object payload */
      data_blocks[i] = (uint8_t *)obj->data + offset;
    } else {
      /* Allocate and zero-pad the final symbol block */
      data_blocks[i] = arena_alloc(&t->arena, symbol_size);
      if (chunk > 0) {
        memcpy(data_blocks[i], (uint8_t *)obj->data + offset, chunk);
      }
    }
  }

  for (size_t i = 0; i < parity_symbols; i++) {
    parity_blocks[i] = arena_alloc(&t->arena, symbol_size);
  }

  if (parity_symbols > 0) {
    if (fec_type == FEC_RAPTORQ && (data_symbols + parity_symbols) <= 255) {
      fec_type = FEC_REED_SOLOMON;
    }
    fec_t *fec =
        get_cached_fec(t, fec_type, data_symbols, parity_symbols, symbol_size);
    if (fec) {
      fec_encode(fec, (const uint8_t *const *)data_blocks, parity_blocks);
    }
  }

  size_t total_symbols = data_symbols + parity_symbols;
  size_t active_count = t->is_server ? t->conn_count : (t->client_conn ? 1 : 0);
  for (size_t c = 0; c < active_count; c++) {
    transport_conn_t *conn = t->is_server ? t->conns[c] : t->client_conn;
    if (!conn || !conn->quic ||
        quicly_get_state(conn->quic) >= QUICLY_STATE_CLOSING)
      continue;
    if (t->is_server && !is_subscribed(conn, &obj->track_id))
      continue;
    uint8_t alias;
    if (find_alias_by_track(conn, &obj->track_id, &alias) != 0)
      continue;
    for (size_t s = 0; s < total_symbols; s++) {
      size_t pkt_len = sizeof(fec_packet_header_t) + symbol_size;
      uint8_t *pkt_buf = arena_alloc(&t->arena, pkt_len);
      fec_packet_header_t *hdr = (fec_packet_header_t *)pkt_buf;

      size_t path_idx = 0;
      size_t accumulated = 0;
      for (size_t i = 0; i < t->num_fds; i++) {
        accumulated += paths_array[i].x;
        if (s < accumulated) {
          path_idx = i;
          break;
        }
      }

      hdr->track_id = alias;
      hdr->is_keyframe = obj->is_keyframe ? 1 : 0;
      hdr->priority = obj->priority;
      hdr->group_id = htobe32((uint32_t)obj->group_id);
      hdr->object_id = htobe32((uint32_t)obj->object_id);
      hdr->symbol_index = htobe16((uint16_t)s);
      hdr->total_symbols = htobe16((uint16_t)total_symbols);
      hdr->data_symbols = htobe16((uint16_t)data_symbols);
      hdr->symbol_size = htobe16((uint16_t)symbol_size);
      hdr->original_size = htobe32((uint32_t)data_size);
      size_t mapped_path_idx = find_path_index_by_link(conn->quic, t, path_idx);
      hdr->path_id = mapped_path_idx;
      hdr->send_time_ns = htobe64(get_time_ns());

      if (s < data_symbols) {
        memcpy(pkt_buf + sizeof(fec_packet_header_t), data_blocks[s],
               symbol_size);
      } else {
        memcpy(pkt_buf + sizeof(fec_packet_header_t),
               parity_blocks[s - data_symbols], symbol_size);
      }

      ptls_iovec_t dgram = ptls_iovec_init(pkt_buf, pkt_len);
      quicly_send_datagram_frames_path(conn->quic, mapped_path_idx, &dgram, 1);
    }
  }

  if (obj->track_id.type == MOQ_TRACK_DATA) {
    sent_object_cache_t *slot = &t->sent_cache[t->sent_cache_index];
    if (slot->data) {
      free(slot->data);
    }
    slot->track_id = obj->track_id;
    slot->group_id = obj->group_id;
    slot->object_id = obj->object_id;
    slot->size = obj->size;
    slot->priority = obj->priority;
    slot->is_keyframe = obj->is_keyframe;
    slot->total_symbols = total_symbols;
    slot->data_symbols = data_symbols;
    slot->symbol_size = symbol_size;
    slot->data = malloc(obj->size);
    if (slot->data) {
      memcpy(slot->data, obj->data, obj->size);
    }
    t->sent_cache_index = (t->sent_cache_index + 1) % SENT_CACHE_SIZE;
  }

  arena_reset(&t->arena);

  return true;
}

bool transport_subscribe(transport_t *t, moq_track_id_t track_id) {
  if (!t)
    return false;

  if (t->is_server) {
    for (size_t i = 0; i < t->conn_count; i++) {
      transport_conn_t *conn = t->conns[i];
      if (!conn || !conn->stream ||
          !quicly_sendstate_is_open(&conn->stream->sendstate))
        continue;

      uint8_t alias;
      if (find_alias_by_track(conn, &track_id, &alias) != 0) {
        if (track_id.name[0] == '\0') {
          alias = (uint8_t)track_id.type;
        } else {
          int next_alias = 8;
          for (int j = 0; j < 32; j++) {
            if (conn->subscriptions[j].active &&
                conn->subscriptions[j].alias >= next_alias) {
              next_alias = conn->subscriptions[j].alias + 1;
            }
          }
          alias = (uint8_t)next_alias;
        }
        add_subscription(conn, track_id.type, track_id.flags, track_id.name,
                         alias);
      }

      uint8_t name_len = (uint8_t)strlen(track_id.name);
      uint8_t msg_hdr[5] = {0x01, alias, (uint8_t)track_id.type, track_id.flags,
                            name_len};
      quicly_streambuf_egress_write(conn->stream, msg_hdr, 5);
      if (name_len > 0) {
        quicly_streambuf_egress_write(conn->stream, track_id.name, name_len);
      }
    }
    return true;
  }

  if (!t->client_conn || !t->client_conn->stream ||
      !quicly_sendstate_is_open(&t->client_conn->stream->sendstate)) {
    return false;
  }

  uint8_t alias;
  if (find_alias_by_track(t->client_conn, &track_id, &alias) != 0) {
    if (track_id.name[0] == '\0') {
      alias = (uint8_t)track_id.type;
    } else {
      int next_alias = 8;
      for (int i = 0; i < 32; i++) {
        if (t->client_conn->subscriptions[i].active &&
            t->client_conn->subscriptions[i].alias >= next_alias) {
          next_alias = t->client_conn->subscriptions[i].alias + 1;
        }
      }
      alias = (uint8_t)next_alias;
    }
    add_subscription(t->client_conn, track_id.type, track_id.flags,
                     track_id.name, alias);
  }

  uint8_t name_len = (uint8_t)strlen(track_id.name);
  uint8_t msg_hdr[5] = {0x01, alias, (uint8_t)track_id.type, track_id.flags,
                        name_len};
  quicly_streambuf_egress_write(t->client_conn->stream, msg_hdr, 5);
  if (name_len > 0) {
    quicly_streambuf_egress_write(t->client_conn->stream, track_id.name,
                                  name_len);
  }
  return true;
}

bool transport_request_keyframe(transport_t *t, moq_track_id_t track_id) {
  if (!t || t->is_server || !t->client_conn || !t->client_conn->stream ||
      !quicly_sendstate_is_open(&t->client_conn->stream->sendstate))
    return false;

  uint8_t name_len = (uint8_t)strlen(track_id.name);
  uint8_t msg_hdr[5] = {0x06, 0, (uint8_t)track_id.type, track_id.flags,
                        name_len};
  quicly_streambuf_egress_write(t->client_conn->stream, msg_hdr, 5);
  if (name_len > 0) {
    quicly_streambuf_egress_write(t->client_conn->stream, track_id.name,
                                  name_len);
  }
  return true;
}

bool transport_send_unicast(transport_t *t, transport_conn_t *conn,
                            const void *data, size_t size) {
  if (!t)
    return false;
  if (!conn || !conn->stream ||
      !quicly_sendstate_is_open(&conn->stream->sendstate))
    return false;

  uint8_t hdr[5];
  hdr[0] = 0x03;
  uint32_t sz = htobe32((uint32_t)size);
  memcpy(hdr + 1, &sz, 4);

  quicly_streambuf_egress_write(conn->stream, hdr, 5);
  quicly_streambuf_egress_write(conn->stream, data, size);
  return true;
}

void transport_close_conn(transport_t *t, transport_conn_t *conn) {
  if (!t)
    return;
  if (conn && conn->quic) {
    quicly_close(conn->quic, 0, "");
  }
}

bool transport_send_auth(transport_t *t, transport_conn_t *conn,
                         const uint8_t *token, size_t token_len) {
  if (!t)
    return false;
  if (!conn || !conn->stream ||
      !quicly_sendstate_is_open(&conn->stream->sendstate))
    return false;
  if (token_len > 65535)
    return false;

  uint8_t hdr[3];
  hdr[0] = 0x04;
  uint16_t t_len = htobe16((uint16_t)token_len);
  memcpy(hdr + 1, &t_len, 2);

  quicly_streambuf_egress_write(conn->stream, hdr, 3);
  if (token_len > 0) {
    quicly_streambuf_egress_write(conn->stream, token, token_len);
  }
  return true;
}

bool transport_respond_auth(transport_t *t, transport_conn_t *conn,
                            bool success) {
  if (!t)
    return false;
  if (!conn || !conn->stream ||
      !quicly_sendstate_is_open(&conn->stream->sendstate))
    return false;

  uint8_t resp[2] = {0x05, success ? 1 : 0};
  quicly_streambuf_egress_write(conn->stream, resp, 2);

  if (success) {
    conn->authenticated = true;
  } else {
    quicly_close(conn->quic, 0, "authentication failed");
  }
  return true;
}

uint64_t transport_get_estimated_bandwidth(transport_t *t) {
  if (!t)
    return 0;
  transport_conn_t *conn =
      t->is_server ? (t->conn_count > 0 ? t->conns[0] : NULL) : t->client_conn;
  if (!conn || !conn->quic) {
    return 0;
  }
  quicly_stats_t stats;
  uint64_t rate = 0;
  if (quicly_get_stats(conn->quic, &stats) == 0) {
    rate = stats.delivery_rate.latest;
  }
  return rate;
}

int transport_enable_qlog(const char *socket_path) {
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    return -1;

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    CLOSE_SOCKET(fd);
    return -1;
  }

  /* Set non-blocking to prevent logging from hanging the main transport thread
   */
  int flags = fcntl(fd, F_GETFL, 0);
  fcntl(fd, F_SETFL, flags | O_NONBLOCK);

  /* enable picotls and quicly tracing, sample ratio 1.0 (all logs), write to fd
   */
  ptls_log_add_fd(fd, 1.0, NULL, NULL, NULL, 0);
  ptls_log_add_fd(fd, 1.0, NULL, NULL, NULL, 1);
  return 0;
}

bool transport_get_path_stats(transport_t *t, size_t path_idx,
                              transport_path_stats_t *stats) {
  if (!t || !stats || path_idx >= t->num_fds)
    return false;

  memset(stats, 0, sizeof(*stats));

  transport_conn_t *target =
      t->is_server ? (t->conn_count > 0 ? t->conns[0] : NULL) : t->client_conn;
  if (target && target->quic) {
    if (path_idx == 0) {
      fprintf(stderr, "=== %s Connection Paths ===\n",
              t->is_server ? "SERVER" : "CLIENT");
      for (size_t p = 0; p < 8; p++) {
        quicly_path_stats_t path_stats;
        if (quicly_get_path_stats(target->quic, p, &path_stats) == 0) {
          char local_ip[64] = {0}, remote_ip[64] = {0};
          if (path_stats.local.sa.sa_family == AF_INET) {
            inet_ntop(AF_INET, &path_stats.local.sin.sin_addr, local_ip,
                      sizeof(local_ip));
            inet_ntop(AF_INET, &path_stats.remote.sin.sin_addr, remote_ip,
                      sizeof(remote_ip));
          }
          fprintf(stderr, "  path %zu: local=%s remote=%s sent=%lu lost=%lu\n",
                  p, local_ip, remote_ip, (unsigned long)path_stats.sent,
                  (unsigned long)path_stats.lost);
        }
      }
    }
    quicly_path_stats_t path_stats;
    size_t mapped_path_idx = find_path_index_by_link(target->quic, t, path_idx);
    if (quicly_get_path_stats(target->quic, mapped_path_idx, &path_stats) ==
        0) {
      stats->sent = path_stats.sent;
      stats->lost = path_stats.lost;
      stats->rtt = path_stats.rtt_smoothed;
    }
  }

  stats->relative_owd =
      (double)FP_TO_FLOAT(t->latest_owd_fp[path_idx]) * 1000.0;
  stats->ewma_latency =
      (double)FP_TO_FLOAT(t->path_states[path_idx].l_ewma) * 1000.0;

  return true;
}

/* mock a local IP interface addition for testing multipath */
void transport_mock_iface_add(transport_t *t, const char *ip_addr) {
  if (!t || t->ifmon_pipe[1] < 0)
    return;

  ifmon_pipe_msg_t msg = {0};
  msg.is_added = 1;
  msg.index = 1; /* loopback interface index */
  struct sockaddr_in *sin = (struct sockaddr_in *)&msg.addr;
  sin->sin_family = AF_INET;
  inet_pton(AF_INET, ip_addr, &sin->sin_addr);
  msg.addr_len = sizeof(*sin);

  ssize_t w = write(t->ifmon_pipe[1], &msg, sizeof(msg));
  (void)w;
}

bool transport_is_track_ready(transport_t *t, const moq_track_id_t *track_id) {
  if (!t)
    return false;

  track_delivery_profile_t profile = get_track_profile(track_id);

  size_t active_count = t->is_server ? t->conn_count : (t->client_conn ? 1 : 0);
  if (active_count == 0)
    return true; /* no peers means data is dropped anyway, so it's "ready" */

  bool all_ready = true;
  for (size_t c = 0; c < active_count; c++) {
    transport_conn_t *conn = t->is_server ? t->conns[c] : t->client_conn;
    if (!conn || !conn->quic ||
        quicly_get_state(conn->quic) >= QUICLY_STATE_CLOSING)
      continue;

    if (t->is_server && !is_subscribed(conn, track_id))
      continue;

    if (profile.reliable) {
      quicly_stream_t *stream = NULL;
      for (int i = 0; i < 32; i++) {
        if (conn->subscriptions[i].active &&
            conn->subscriptions[i].track_id.type == track_id->type &&
            strcmp(conn->subscriptions[i].track_id.name, track_id->name) == 0) {
          stream = conn->subscriptions[i].stream;
          break;
        }
      }

      if (stream) {
        quicly_streambuf_t *sbuf = (quicly_streambuf_t *)stream->data;
        if (sbuf && sbuf->egress.vecs.size > 256) {
          all_ready = false;
          break;
        }
      }
    } else {
      quicly_path_stats_t pstats;
      if (quicly_get_path_stats(conn->quic, 0, &pstats) == 0) {
        if (pstats.bytes_in_flight >= pstats.cwnd * 2) {
          all_ready = false;
          break;
        }
      }
    }
  }

  return all_ready;
}
