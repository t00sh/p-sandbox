#ifndef DEF_SANDBOX_H
#define DEF_SANDBOX_H

#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>
#include "types.h"

struct sandbox {
  pid_t pid;
  int argc;
  char **argv;
  bool trace;
  FILE *log;
};

void sandbox_init(struct sandbox *sandb);
void sandbox_run(struct sandbox *sandb);
void sandbox_dump_address(struct sandbox *sandb,
                          long address, size_t length);
#endif /* DEF_SANDBOX_H */
