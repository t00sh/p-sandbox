#include <ctype.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include "log.h"
#include "syscalls.h"

void hexdump_buffer(FILE *stream, uint8_t *buffer, size_t length) {
  size_t i, j;

  for(i = 0; i < length; i += 16) {
    LOG(stream, " ");
    for(j = 0; j < 16; j++) {
      if(i + j < length) {
        LOG_APPEND(stream, "%.2" PRIx8 " ", buffer[i + j]);
      } else {
        LOG_APPEND(stream, "   ");
      }
    }
    for(j = 0; j < 16; j++) {
      if(i + j < length) {
        if(isgraph(buffer[i + j])) {
          LOG_APPEND(stream, "%c", (char) buffer[i + j]);
        } else {
          LOG_APPEND(stream, ".");
        }
      }
    }
    LOG_APPEND(stream, "\n");
  }
  LOG_APPEND(stream, "\n");
}
