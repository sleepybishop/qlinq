/* qlinq-cast: finite file and stdin fan-out over the native stream API. */

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "cli_parse.h"
#include "qlinq.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define CAST_DEFAULT_PORT 9000U
#define CAST_DEFAULT_BLOCK_SIZE 16384U
#define CAST_MAX_BLOCK_SIZE 60000U
#define CAST_DEFAULT_IDLE_TIMEOUT_MS 60000U
#define CAST_REORDER_SLOTS 4096U
#define CAST_REORDER_MAX_BYTES (64U * 1024U * 1024U)
#define CAST_MAX_SECRET_SIZE 65535U

typedef enum { CAST_SEND, CAST_RECEIVE } cast_command_t;

typedef struct {
  uint8_t *data;
  size_t size;
  uint64_t sequence;
  bool active;
} cast_reorder_entry_t;

typedef struct {
  cast_command_t command;
  const char *path;
  const char *bind_addresses[QLINQ_MAX_PATHS];
  size_t bind_count;
  const char *peer_arguments[QLINQ_MAX_PATHS];
  char peer_addresses[QLINQ_MAX_PATHS][256];
  size_t peer_count;
  uint16_t port;
  bool port_explicit;
  const char *certificate_file;
  const char *private_key_file;
  const char *trust_store_file;
  const char *secret_text;
  const char *secret_file;
  uint8_t *owned_secret;
  size_t secret_size;
  const char *stream_name;
  qlinq_delivery_t delivery;
  qlinq_repair_mode_t repair_mode;
  uint64_t idle_timeout_ms;
  size_t block_size;
  size_t wait_receivers;
  size_t max_connections;
  size_t max_repair_requests;
  size_t max_aggregate_repairs;
  bool insecure;
  bool verbose;
  uint32_t stats_ms;
  bool flexicast;
  const char *flexicast_group;
  uint16_t flexicast_port;
  const char *flexicast_interface;
  qlinq_group_cc_t flexicast_cc;
  uint64_t flexicast_startup_rate;
  uint64_t flexicast_minimum_rate;
  uint64_t flexicast_maximum_rate;
  uint64_t flexicast_aggregate_rate;
  uint32_t flexicast_feedback_timeout_ms;
} cast_options_t;

typedef struct {
  cast_options_t options;
  qlinq_context_t *context;
  qlinq_endpoint_t *endpoint;
  qlinq_stream_t *stream;
  FILE *file;
  uint8_t *pending;
  size_t pending_size;
  uint64_t next_sequence;
  uint64_t records;
  uint64_t bytes;
  uint64_t started_ms;
  uint64_t next_stats_ms;
  bool input_eof;
  bool finishing;
  bool complete;
  bool failed;
  size_t peers_total;
  size_t peers_completed;
  size_t peers_failed;
  cast_reorder_entry_t reorder[CAST_REORDER_SLOTS];
  size_t reorder_bytes;
} cast_runtime_t;

static volatile sig_atomic_t cast_running = 1;

static void handle_signal(int signal_number) {
  (void)signal_number;
  cast_running = 0;
}

static uint64_t monotonic_ms(void) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
    return 0;
  return (uint64_t)now.tv_sec * 1000U + (uint64_t)now.tv_nsec / 1000000U;
}

static void show_help(FILE *output, const char *program) {
  fprintf(
      output,
      "usage: %s send [options] INPUT|-\n"
      "       %s receive [options] OUTPUT|-\n\n"
      "Common options:\n"
      "  --bind ADDRESS                 local address (repeatable)\n"
      "  --port PORT                    control port (default 9000)\n"
      "  --secret TEXT                  shared application secret\n"
      "  --secret-file FILE             read shared secret from a file\n"
      "  --stream NAME                  stream name (default qlinq-cast/data)\n"
      "  --mode rateless|fec            delivery mode (default rateless)\n"
      "  --repair-mode auto|rateless|indexed\n"
      "  --idle-timeout-ms MS           control connection idle timeout\n"
      "  --stats-ms MS                  print periodic progress; 0 disables\n"
      "  --verbose                      print peer and lifecycle events\n"
      "  --insecure                     disable peer certificate "
      "verification\n\n"
      "TLS options:\n"
      "  --cert FILE --key FILE         local identity (sender requires both)\n"
      "  --ca FILE                      peer CA bundle\n\n"
      "Sender options:\n"
      "  --block-size BYTES             record size (default 16384)\n"
      "  --wait-receivers N             cohort size before reading (default "
      "1)\n"
      "  --max-connections N            accepted peer capacity\n\n"
      "Receiver options:\n"
      "  --peer ADDRESS[:PORT]          sender path (repeatable, required)\n\n"
      "Recovery limits:\n"
      "  --max-repair-requests N        per-receiver requests/second\n"
      "  --max-aggregate-repairs N      sender-wide requests/second\n\n"
      "Group delivery:\n"
      "  --flexicast\n"
      "  --flexicast-group GROUP --flexicast-port PORT\n"
      "  --flexicast-interface ADDRESS\n"
      "  --flexicast-cc conservative|adaptive\n"
      "  --flexicast-startup-rate BYTES_PER_SECOND\n"
      "  --flexicast-min-rate BYTES_PER_SECOND\n"
      "  --flexicast-max-rate BYTES_PER_SECOND\n"
      "  --flexicast-aggregate-rate BYTES_PER_SECOND\n"
      "  --flexicast-feedback-timeout MS\n\n"
      "QLINQ_CAST_SECRET supplies the secret when neither secret option is "
      "given.\n",
      program, program);
}

static bool read_secret(cast_options_t *options) {
  if (options->secret_text) {
    options->secret_size = strlen(options->secret_text);
    return options->secret_size != 0 &&
           options->secret_size <= CAST_MAX_SECRET_SIZE;
  }
  if (!options->secret_file) {
    options->secret_text = getenv("QLINQ_CAST_SECRET");
    if (!options->secret_text)
      return false;
    options->secret_size = strlen(options->secret_text);
    return options->secret_size != 0 &&
           options->secret_size <= CAST_MAX_SECRET_SIZE;
  }

  FILE *secret = fopen(options->secret_file, "rb");
  if (!secret)
    return false;
  uint8_t *data = malloc(CAST_MAX_SECRET_SIZE + 1U);
  if (!data) {
    fclose(secret);
    return false;
  }
  size_t size = fread(data, 1, CAST_MAX_SECRET_SIZE + 1U, secret);
  bool read_ok = !ferror(secret) && size <= CAST_MAX_SECRET_SIZE;
  fclose(secret);
  while (size != 0 && (data[size - 1U] == '\n' || data[size - 1U] == '\r'))
    size--;
  if (!read_ok || size == 0) {
    free(data);
    return false;
  }
  options->owned_secret = data;
  options->secret_text = (const char *)data;
  options->secret_size = size;
  return true;
}

static bool require_value(int argc, char **argv, int *index,
                          const char **value) {
  if (*index + 1 >= argc)
    return false;
  *value = argv[++*index];
  return true;
}

static bool parse_options(int argc, char **argv, cast_options_t *options) {
  memset(options, 0, sizeof(*options));
  options->port = CAST_DEFAULT_PORT;
  options->stream_name = "qlinq-cast/data";
  options->delivery = QLINQ_DELIVERY_RATELESS;
  options->repair_mode = QLINQ_REPAIR_AUTO;
  options->idle_timeout_ms = CAST_DEFAULT_IDLE_TIMEOUT_MS;
  options->block_size = CAST_DEFAULT_BLOCK_SIZE;
  options->wait_receivers = 1;
  options->flexicast_cc = QLINQ_GROUP_CC_CONSERVATIVE;

  if (argc < 2)
    return false;
  if (strcmp(argv[1], "send") == 0)
    options->command = CAST_SEND;
  else if (strcmp(argv[1], "receive") == 0)
    options->command = CAST_RECEIVE;
  else
    return false;

  for (int i = 2; i < argc; i++) {
    const char *value = NULL;
    uint64_t parsed = 0;
    if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0)
      return false;
    if (strcmp(argv[i], "--bind") == 0) {
      if (!require_value(argc, argv, &i, &value) ||
          options->bind_count == QLINQ_MAX_PATHS)
        return false;
      options->bind_addresses[options->bind_count++] = value;
    } else if (strcmp(argv[i], "--peer") == 0) {
      if (!require_value(argc, argv, &i, &value) ||
          options->peer_count == QLINQ_MAX_PATHS)
        return false;
      options->peer_arguments[options->peer_count++] = value;
    } else if (strcmp(argv[i], "--port") == 0) {
      if (!require_value(argc, argv, &i, &value) ||
          !cli_parse_u64(value, UINT16_MAX, &parsed) || parsed == 0)
        return false;
      options->port = (uint16_t)parsed;
      options->port_explicit = true;
    } else if (strcmp(argv[i], "--cert") == 0) {
      if (!require_value(argc, argv, &i, &options->certificate_file))
        return false;
    } else if (strcmp(argv[i], "--key") == 0) {
      if (!require_value(argc, argv, &i, &options->private_key_file))
        return false;
    } else if (strcmp(argv[i], "--ca") == 0) {
      if (!require_value(argc, argv, &i, &options->trust_store_file))
        return false;
    } else if (strcmp(argv[i], "--secret") == 0) {
      if (!require_value(argc, argv, &i, &options->secret_text))
        return false;
    } else if (strcmp(argv[i], "--secret-file") == 0) {
      if (!require_value(argc, argv, &i, &options->secret_file))
        return false;
    } else if (strcmp(argv[i], "--stream") == 0) {
      if (!require_value(argc, argv, &i, &options->stream_name))
        return false;
    } else if (strcmp(argv[i], "--mode") == 0) {
      if (!require_value(argc, argv, &i, &value))
        return false;
      if (strcmp(value, "rateless") == 0)
        options->delivery = QLINQ_DELIVERY_RATELESS;
      else if (strcmp(value, "fec") == 0)
        options->delivery = QLINQ_DELIVERY_FIXED_FEC;
      else
        return false;
    } else if (strcmp(argv[i], "--repair-mode") == 0) {
      if (!require_value(argc, argv, &i, &value))
        return false;
      if (strcmp(value, "auto") == 0)
        options->repair_mode = QLINQ_REPAIR_AUTO;
      else if (strcmp(value, "rateless") == 0)
        options->repair_mode = QLINQ_REPAIR_RATELESS;
      else if (strcmp(value, "indexed") == 0)
        options->repair_mode = QLINQ_REPAIR_INDEXED;
      else
        return false;
    } else if (strcmp(argv[i], "--idle-timeout-ms") == 0) {
      if (!require_value(argc, argv, &i, &value) ||
          !cli_parse_u64(value, UINT64_MAX, &options->idle_timeout_ms))
        return false;
    } else if (strcmp(argv[i], "--block-size") == 0) {
      if (!require_value(argc, argv, &i, &value) ||
          !cli_parse_u64(value, CAST_MAX_BLOCK_SIZE, &parsed) || parsed == 0)
        return false;
      options->block_size = (size_t)parsed;
    } else if (strcmp(argv[i], "--wait-receivers") == 0) {
      if (!require_value(argc, argv, &i, &value) ||
          !cli_parse_u64(value, 16384U, &parsed) || parsed == 0)
        return false;
      options->wait_receivers = (size_t)parsed;
    } else if (strcmp(argv[i], "--max-connections") == 0) {
      if (!require_value(argc, argv, &i, &value) ||
          !cli_parse_u64(value, 16384U, &parsed) || parsed == 0)
        return false;
      options->max_connections = (size_t)parsed;
    } else if (strcmp(argv[i], "--max-repair-requests") == 0) {
      if (!require_value(argc, argv, &i, &value) ||
          !cli_parse_u64(value, UINT16_MAX, &parsed) || parsed == 0)
        return false;
      options->max_repair_requests = (size_t)parsed;
    } else if (strcmp(argv[i], "--max-aggregate-repairs") == 0) {
      if (!require_value(argc, argv, &i, &value) ||
          !cli_parse_u64(value, UINT16_MAX, &parsed) || parsed == 0)
        return false;
      options->max_aggregate_repairs = (size_t)parsed;
    } else if (strcmp(argv[i], "--stats-ms") == 0) {
      if (!require_value(argc, argv, &i, &value) ||
          !cli_parse_u64(value, UINT32_MAX, &parsed))
        return false;
      options->stats_ms = (uint32_t)parsed;
    } else if (strcmp(argv[i], "--verbose") == 0) {
      options->verbose = true;
    } else if (strcmp(argv[i], "--insecure") == 0) {
      options->insecure = true;
    } else if (strcmp(argv[i], "--flexicast") == 0) {
      options->flexicast = true;
    } else if (strcmp(argv[i], "--flexicast-group") == 0) {
      if (!require_value(argc, argv, &i, &options->flexicast_group))
        return false;
      options->flexicast = true;
    } else if (strcmp(argv[i], "--flexicast-port") == 0) {
      if (!require_value(argc, argv, &i, &value) ||
          !cli_parse_u64(value, UINT16_MAX, &parsed) || parsed == 0)
        return false;
      options->flexicast_port = (uint16_t)parsed;
      options->flexicast = true;
    } else if (strcmp(argv[i], "--flexicast-interface") == 0) {
      if (!require_value(argc, argv, &i, &options->flexicast_interface))
        return false;
      options->flexicast = true;
    } else if (strcmp(argv[i], "--flexicast-cc") == 0) {
      if (!require_value(argc, argv, &i, &value))
        return false;
      if (strcmp(value, "conservative") == 0)
        options->flexicast_cc = QLINQ_GROUP_CC_CONSERVATIVE;
      else if (strcmp(value, "adaptive") == 0)
        options->flexicast_cc = QLINQ_GROUP_CC_ADAPTIVE;
      else
        return false;
      options->flexicast = true;
    } else if (strcmp(argv[i], "--flexicast-startup-rate") == 0) {
      if (!require_value(argc, argv, &i, &value) ||
          !cli_parse_u64(value, UINT64_MAX, &options->flexicast_startup_rate))
        return false;
      options->flexicast = true;
    } else if (strcmp(argv[i], "--flexicast-min-rate") == 0) {
      if (!require_value(argc, argv, &i, &value) ||
          !cli_parse_u64(value, UINT64_MAX, &options->flexicast_minimum_rate))
        return false;
      options->flexicast = true;
    } else if (strcmp(argv[i], "--flexicast-max-rate") == 0) {
      if (!require_value(argc, argv, &i, &value) ||
          !cli_parse_u64(value, UINT64_MAX, &options->flexicast_maximum_rate))
        return false;
      options->flexicast = true;
    } else if (strcmp(argv[i], "--flexicast-aggregate-rate") == 0) {
      if (!require_value(argc, argv, &i, &value) ||
          !cli_parse_u64(value, UINT64_MAX, &options->flexicast_aggregate_rate))
        return false;
      options->flexicast = true;
    } else if (strcmp(argv[i], "--flexicast-feedback-timeout") == 0) {
      if (!require_value(argc, argv, &i, &value) ||
          !cli_parse_u64(value, UINT32_MAX, &parsed))
        return false;
      options->flexicast_feedback_timeout_ms = (uint32_t)parsed;
      options->flexicast = true;
    } else if (argv[i][0] == '-' && strcmp(argv[i], "-") != 0) {
      return false;
    } else if (options->path) {
      return false;
    } else {
      options->path = argv[i];
    }
  }

  if (!options->path || !options->stream_name[0] ||
      strlen(options->stream_name) >= QLINQ_STREAM_NAME_CAPACITY ||
      (options->secret_text && options->secret_file) ||
      (!!options->certificate_file != !!options->private_key_file) ||
      (options->command == CAST_SEND &&
       (!options->certificate_file || !options->private_key_file ||
        options->peer_count != 0)) ||
      (options->command == CAST_RECEIVE && options->peer_count == 0) ||
      (options->max_connections != 0 &&
       options->max_connections < options->wait_receivers) ||
      (options->flexicast_group &&
       (!options->flexicast_port || !options->flexicast_interface)) ||
      (!options->flexicast_group && options->flexicast_port != 0))
    return false;

  if (options->bind_count == 0)
    options->bind_addresses[options->bind_count++] = "0.0.0.0";

  uint16_t peer_port = options->port;
  bool embedded_port_seen = false;
  for (size_t i = 0; i < options->peer_count; i++) {
    bool has_port = false;
    uint16_t parsed_port = 0;
    if (!cli_parse_endpoint(
            options->peer_arguments[i], options->peer_addresses[i],
            sizeof(options->peer_addresses[i]), &parsed_port, &has_port))
      return false;
    if (has_port) {
      if (options->port_explicit && parsed_port != options->port)
        return false;
      if (embedded_port_seen && parsed_port != peer_port)
        return false;
      peer_port = parsed_port;
      embedded_port_seen = true;
    }
  }
  if (embedded_port_seen)
    options->port = peer_port;
  if (options->command == CAST_SEND && options->max_connections == 0 &&
      options->wait_receivers > 32U)
    options->max_connections = options->wait_receivers;
  return read_secret(options);
}

static void print_options_error(const char *program) {
  fprintf(stderr,
          "%s: invalid arguments or missing secret; use --help for usage\n",
          program);
}

static bool open_runtime(cast_runtime_t *runtime) {
  cast_options_t *options = &runtime->options;
  runtime->context = qlinq_context_create(NULL);
  if (!runtime->context)
    return false;

  qlinq_endpoint_config_t endpoint_config = {
      .port = options->port,
      .idle_timeout_ms = options->idle_timeout_ms,
      .security = {.shared_secret = options->secret_text,
                   .shared_secret_size = options->secret_size,
                   .certificate_file = options->certificate_file,
                   .private_key_file = options->private_key_file,
                   .trust_store_file = options->trust_store_file,
                   .verify_peer = !options->insecure,
                   .allow_insecure_peer = options->insecure},
      .group_delivery =
          {.enabled = options->flexicast,
           .group_address = options->flexicast_group,
           .port = options->flexicast_port,
           .interface_address = options->flexicast_interface,
           .congestion_control = options->flexicast_cc,
           .startup_rate_bytes_per_second = options->flexicast_startup_rate,
           .minimum_rate_bytes_per_second = options->flexicast_minimum_rate,
           .maximum_rate_bytes_per_second = options->flexicast_maximum_rate,
           .aggregate_rate_bytes_per_second = options->flexicast_aggregate_rate,
           .feedback_timeout_ms = options->flexicast_feedback_timeout_ms},
      .repair_mode = options->repair_mode,
      .limits = {.max_connections = options->max_connections,
                 .max_repair_requests_per_second = options->max_repair_requests,
                 .max_aggregate_repair_requests_per_second =
                     options->max_aggregate_repairs}};
  for (size_t i = 0; i < options->bind_count; i++)
    endpoint_config.bind_addresses[endpoint_config.bind_address_count++] =
        options->bind_addresses[i];
  for (size_t i = 0; i < options->peer_count; i++)
    endpoint_config.remote_addresses[endpoint_config.remote_address_count++] =
        options->peer_addresses[i];

  runtime->endpoint = options->command == CAST_SEND
                          ? qlinq_listen(runtime->context, &endpoint_config)
                          : qlinq_connect(runtime->context, &endpoint_config);
  if (!runtime->endpoint)
    return false;

  qlinq_stream_config_t stream_config = {.content_type = QLINQ_CONTENT_DATA,
                                         .delivery = options->delivery,
                                         .name = options->stream_name};
  runtime->stream = options->command == CAST_SEND
                        ? qlinq_publish(runtime->endpoint, &stream_config)
                        : qlinq_subscribe(runtime->endpoint, &stream_config);
  if (!runtime->stream)
    return false;

  runtime->file = strcmp(options->path, "-") == 0
                      ? (options->command == CAST_SEND ? stdin : stdout)
                  : options->command == CAST_SEND ? fopen(options->path, "rb")
                                                  : fopen(options->path, "wb");
  if (!runtime->file)
    return false;
  if (options->command == CAST_SEND) {
    runtime->pending = malloc(options->block_size);
    if (!runtime->pending)
      return false;
    int descriptor = fileno(runtime->file);
    int flags = fcntl(descriptor, F_GETFL, 0);
    if (flags >= 0)
      (void)fcntl(descriptor, F_SETFL, flags | O_NONBLOCK);
  }
  runtime->started_ms = monotonic_ms();
  runtime->next_stats_ms = runtime->started_ms + options->stats_ms;
  return true;
}

static void close_runtime(cast_runtime_t *runtime) {
  if (runtime->file && runtime->file != stdin && runtime->file != stdout)
    fclose(runtime->file);
  for (size_t i = 0; i < CAST_REORDER_SLOTS; i++)
    free(runtime->reorder[i].data);
  qlinq_context_destroy(runtime->context);
  free(runtime->pending);
  free(runtime->options.owned_secret);
}

static void print_progress(cast_runtime_t *runtime, bool final) {
  if (!final && runtime->options.stats_ms == 0)
    return;
  uint64_t now = monotonic_ms();
  if (!final && now < runtime->next_stats_ms)
    return;
  qlinq_stream_stats_t stream_stats = {0};
  qlinq_endpoint_stats_t endpoint_stats = {0};
  (void)qlinq_stream_get_stats(runtime->stream, &stream_stats);
  (void)qlinq_endpoint_get_stats(runtime->endpoint, &endpoint_stats);
  fprintf(stderr,
          "qlinq-cast: %s records=%" PRIu64 " bytes=%" PRIu64
          " peers=%zu group-members=%zu queued=%zu lost=%" PRIu64 "%s\n",
          runtime->options.command == CAST_SEND ? "sent" : "received",
          runtime->records, runtime->bytes,
          runtime->options.command == CAST_SEND
              ? stream_stats.subscribers
              : endpoint_stats.active_connections,
          stream_stats.group_members, endpoint_stats.queued_packets,
          stream_stats.objects_lost, final ? " final" : "");
  runtime->next_stats_ms = now + runtime->options.stats_ms;
}

static bool write_record(cast_runtime_t *runtime,
                         const qlinq_record_t *record) {
  if (record->sequence < runtime->next_sequence)
    return true;
  uint64_t distance = record->sequence - runtime->next_sequence;
  if (distance >= CAST_REORDER_SLOTS ||
      record->size > CAST_REORDER_MAX_BYTES - runtime->reorder_bytes)
    return false;
  size_t slot = (size_t)(record->sequence % CAST_REORDER_SLOTS);
  cast_reorder_entry_t *entry = &runtime->reorder[slot];
  if (entry->active)
    return entry->sequence == record->sequence;
  entry->data = malloc(record->size);
  if (!entry->data)
    return false;
  memcpy(entry->data, record->data, record->size);
  entry->size = record->size;
  entry->sequence = record->sequence;
  entry->active = true;
  runtime->reorder_bytes += record->size;

  while (true) {
    slot = (size_t)(runtime->next_sequence % CAST_REORDER_SLOTS);
    entry = &runtime->reorder[slot];
    if (!entry->active || entry->sequence != runtime->next_sequence)
      break;
    if (entry->size != 0 &&
        fwrite(entry->data, 1, entry->size, runtime->file) != entry->size)
      return false;
    runtime->records++;
    runtime->bytes += entry->size;
    runtime->reorder_bytes -= entry->size;
    free(entry->data);
    memset(entry, 0, sizeof(*entry));
    runtime->next_sequence++;
  }
  return true;
}

static void handle_event(cast_runtime_t *runtime, qlinq_event_t *event) {
  if (runtime->options.verbose) {
    if (event->type == QLINQ_EVENT_PEER_READY)
      fprintf(stderr, "qlinq-cast: peer %u ready\n", event->peer_id);
    else if (event->type == QLINQ_EVENT_SUBSCRIBER_JOINED)
      fprintf(stderr, "qlinq-cast: receiver %u joined\n", event->peer_id);
    else if (event->type == QLINQ_EVENT_SUBSCRIBER_LEFT)
      fprintf(stderr, "qlinq-cast: receiver %u left\n", event->peer_id);
  }

  switch (event->type) {
  case QLINQ_EVENT_RECORD:
    if (runtime->options.command == CAST_RECEIVE &&
        event->stream == runtime->stream &&
        !write_record(runtime, &event->record)) {
      fprintf(stderr, "qlinq-cast: output or receive reorder limit failed\n");
      runtime->failed = true;
    }
    break;
  case QLINQ_EVENT_STREAM_FINISHED:
    if (runtime->options.command == CAST_RECEIVE &&
        event->stream == runtime->stream) {
      if (runtime->reorder_bytes != 0 || fflush(runtime->file) != 0) {
        fprintf(stderr, "qlinq-cast: completion has an unwritten record gap\n");
        runtime->failed = true;
      } else {
        runtime->complete = true;
      }
    }
    break;
  case QLINQ_EVENT_STREAM_DRAINED:
    if (runtime->options.command == CAST_SEND &&
        event->stream == runtime->stream) {
      runtime->peers_total = event->completion.peers_total;
      runtime->peers_completed = event->completion.peers_completed;
      runtime->peers_failed = event->completion.peers_failed;
      runtime->complete = true;
      if (runtime->peers_failed != 0)
        runtime->failed = true;
    }
    break;
  case QLINQ_EVENT_STREAM_ABORTED:
    if (event->stream == runtime->stream) {
      fprintf(stderr, "qlinq-cast: transfer aborted\n");
      runtime->failed = true;
    }
    break;
  case QLINQ_EVENT_PEER_REJECTED:
    if (runtime->options.command == CAST_RECEIVE) {
      fprintf(stderr, "qlinq-cast: sender rejected authentication\n");
      runtime->failed = true;
    } else if (runtime->options.verbose) {
      fprintf(stderr, "qlinq-cast: rejected peer %u\n", event->peer_id);
    }
    break;
  case QLINQ_EVENT_PEER_DISCONNECTED:
    if (runtime->options.command == CAST_RECEIVE && !runtime->complete) {
      fprintf(stderr, "qlinq-cast: sender disconnected before completion\n");
      runtime->failed = true;
    }
    break;
  case QLINQ_EVENT_RECORD_LOST:
    if (runtime->options.command == CAST_RECEIVE &&
        event->stream == runtime->stream) {
      fprintf(stderr, "qlinq-cast: record recovery failed\n");
      runtime->failed = true;
    }
    break;
  case QLINQ_EVENT_ERROR:
    fprintf(stderr, "qlinq-cast: %s\n",
            event->message ? event->message : "endpoint error");
    runtime->failed = true;
    break;
  case QLINQ_EVENT_PEER_READY:
  case QLINQ_EVENT_SUBSCRIBER_JOINED:
  case QLINQ_EVENT_SUBSCRIBER_LEFT:
  case QLINQ_EVENT_KEYFRAME_REQUESTED:
  case QLINQ_EVENT_STREAM_WRITABLE:
    break;
  }
}

static void drain_events(cast_runtime_t *runtime) {
  qlinq_event_t event;
  while (qlinq_next_event(runtime->context, &event)) {
    handle_event(runtime, &event);
    qlinq_event_release(&event);
  }
}

static bool sender_ready(cast_runtime_t *runtime) {
  qlinq_stream_stats_t stats;
  return qlinq_stream_get_stats(runtime->stream, &stats) &&
         stats.state == QLINQ_STREAM_OPEN &&
         stats.subscribers >= runtime->options.wait_receivers;
}

static bool pump_sender(cast_runtime_t *runtime) {
  if (runtime->finishing || runtime->failed || !sender_ready(runtime))
    return false;

  if (runtime->pending_size == 0 && !runtime->input_eof) {
    ssize_t received = read(fileno(runtime->file), runtime->pending,
                            runtime->options.block_size);
    if (received > 0) {
      runtime->pending_size = (size_t)received;
    } else if (received == 0) {
      runtime->input_eof = true;
    } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
      fprintf(stderr, "qlinq-cast: input read failed: %s\n", strerror(errno));
      runtime->failed = true;
      return false;
    }
  }

  if (runtime->pending_size != 0) {
    qlinq_record_t record = {.group_id = 0,
                             .sequence = runtime->next_sequence,
                             .data = runtime->pending,
                             .size = runtime->pending_size,
                             .priority = 1};
    qlinq_send_result_t result = qlinq_stream_send(runtime->stream, &record);
    if (result == QLINQ_SEND_SENT || result == QLINQ_SEND_BUFFERED ||
        result == QLINQ_SEND_PARTIAL) {
      runtime->records++;
      runtime->bytes += runtime->pending_size;
      runtime->next_sequence++;
      runtime->pending_size = 0;
      return true;
    } else if (result != QLINQ_SEND_WOULD_BLOCK &&
               result != QLINQ_SEND_NO_SUBSCRIBERS) {
      fprintf(stderr, "qlinq-cast: stream send failed (%d)\n", (int)result);
      runtime->failed = true;
    }
    return false;
  }

  if (runtime->input_eof &&
      qlinq_stream_finish(runtime->stream) == QLINQ_STATUS_OK) {
    runtime->finishing = true;
    if (runtime->options.verbose)
      fprintf(stderr, "qlinq-cast: input complete; waiting for receivers\n");
    return true;
  }
  return false;
}

static int run_cast(cast_runtime_t *runtime) {
  while (cast_running && !runtime->complete && !runtime->failed) {
    bool made_progress = false;
    if (runtime->options.command == CAST_SEND)
      made_progress = pump_sender(runtime);
    qlinq_status_t status =
        qlinq_service(runtime->context, made_progress ? 0 : 10);
    if (status < 0 && status != QLINQ_STATUS_STATE) {
      fprintf(stderr, "qlinq-cast: service failed (%d)\n", (int)status);
      runtime->failed = true;
    }
    drain_events(runtime);
    print_progress(runtime, false);
  }

  if (!cast_running && !runtime->complete && runtime->stream) {
    if (runtime->options.command == CAST_SEND)
      (void)qlinq_stream_abort(runtime->stream);
    for (unsigned int i = 0; i < 20; i++) {
      (void)qlinq_service(runtime->context, 10);
      drain_events(runtime);
    }
  }
  print_progress(runtime, true);
  if (!cast_running)
    return 130;
  return runtime->failed || !runtime->complete ? 2 : 0;
}

int main(int argc, char **argv) {
  for (int i = 1; i < argc; i++)
    if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      show_help(stdout, argv[0]);
      return 0;
    }

  cast_runtime_t runtime;
  memset(&runtime, 0, sizeof(runtime));
  if (!parse_options(argc, argv, &runtime.options)) {
    print_options_error(argv[0]);
    free(runtime.options.owned_secret);
    return 1;
  }

  signal(SIGINT, handle_signal);
  signal(SIGTERM, handle_signal);
  if (!open_runtime(&runtime)) {
    fprintf(stderr, "qlinq-cast: unable to initialize transfer: %s\n",
            strerror(errno));
    close_runtime(&runtime);
    return 1;
  }

  int result = run_cast(&runtime);
  if (result == 0 && runtime.options.command == CAST_SEND)
    fprintf(stderr,
            "qlinq-cast: delivery complete: receivers=%zu confirmed=%zu "
            "failed=%zu\n",
            runtime.peers_total, runtime.peers_completed, runtime.peers_failed);
  close_runtime(&runtime);
  return result;
}
