#ifndef DEF_SANDBOX_H
#define DEF_SANDBOX_H

#include <sys/types.h>
#include "types.h"

struct sandbox {
  pid_t pid;
  int argc;
  char **argv;
};

void sandbox_init(struct sandbox *sandb, int argc, char **argv);
void sandbox_run(struct sandbox *sandb);
void sandbox_dump_address(struct sandbox *sandb,
                          regint address, regint length);
#endif /* DEF_SANDBOX_H */
