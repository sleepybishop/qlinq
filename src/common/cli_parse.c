#include "cli_parse.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

bool cli_parse_u64(const char *text, uint64_t maximum, uint64_t *value) {
  char *end = NULL;
  if (!text || !text[0] || text[0] == '-' || !value)
    return false;
  errno = 0;
  unsigned long long parsed = strtoull(text, &end, 10);
  if (errno != 0 || !end || *end != '\0' || parsed > maximum)
    return false;
  *value = (uint64_t)parsed;
  return true;
}

bool cli_parse_endpoint(const char *text, char *host, size_t host_capacity,
                        uint16_t *port, bool *has_port) {
  if (!text || !text[0] || !host || host_capacity == 0 || !port)
    return false;
  const char *start = text;
  const char *port_text = NULL;
  size_t host_size = strlen(text);
  if (text[0] == '[') {
    const char *closing = strchr(text + 1, ']');
    if (!closing || (closing[1] != '\0' && closing[1] != ':'))
      return false;
    start = text + 1;
    host_size = (size_t)(closing - start);
    if (closing[1] == ':')
      port_text = closing + 2;
  } else {
    const char *first_colon = strchr(text, ':');
    if (first_colon && first_colon == strrchr(text, ':')) {
      host_size = (size_t)(first_colon - text);
      port_text = first_colon + 1;
    }
  }
  if (host_size == 0 || host_size >= host_capacity)
    return false;
  if (has_port)
    *has_port = port_text != NULL;
  if (port_text) {
    uint64_t parsed;
    if (!cli_parse_u64(port_text, UINT16_MAX, &parsed) || parsed == 0)
      return false;
    *port = (uint16_t)parsed;
  }
  memcpy(host, start, host_size);
  host[host_size] = '\0';
  return true;
}
