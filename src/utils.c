#include <ctype.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include "syscalls.h"

void hexdump_buffer(uint8_t *buffer, regint length) {
  regint i, j;

  for(i = 0; i < length; i += 16) {
    printf("[SANDBOX] ");
    for(j = 0; j < 16; j++) {
      if(i + j < length) {
        printf("%.2" PRIx8 " ", buffer[i + j]);
      } else {
        printf("%-3s", " ");
      }
    }
    for(j = 0; j < 16; j++) {
      if(i + j < length) {
        if(isgraph(buffer[i + j])) {
          putchar(buffer[i + j]);
        } else {
          putchar('.');
        }
      }
    }
    printf("\n");
  }
  printf("\n");
}
