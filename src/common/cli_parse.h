#ifndef QLINQ_CLI_PARSE_H
#define QLINQ_CLI_PARSE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool cli_parse_u64(const char *text, uint64_t maximum, uint64_t *value);

/* Parses HOST, HOST:PORT, [IPv6], or [IPv6]:PORT. The caller supplies the
 * default port; has_port may be NULL when that distinction is unimportant. */
bool cli_parse_endpoint(const char *text, char *host, size_t host_capacity,
                        uint16_t *port, bool *has_port);

#endif
