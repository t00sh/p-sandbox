#include <err.h>
#include <stdlib.h>
#include <stdio.h>

#include "sandbox.h"
#include "syscalls.h"

int main(int argc, char **argv) {
  struct sandbox sandb;

  if(argc < 2) {
    errx(EXIT_FAILURE, "[SANDBOX] Usage : %s <elf> [<arg1...>]", argv[0]);
  }

  syscalls_init();
  sandbox_init(&sandb, argc-1, argv+1);

  for(;;) {
    sandbox_run(&sandb);
  }

  return EXIT_SUCCESS;
}
