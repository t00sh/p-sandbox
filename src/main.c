#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>

#include "sandbox.h"
#include "syscalls.h"
#include "log.h"
#include "handlers.h"

static void usage(const char *progname, int exit_status) {
  LOGN(stdout, "Usage : %s [OPTIONS] <cmd> [<arg1>, ...]", progname);
  LOGN(stdout, "OPTIONS");
  LOGN(stdout, "  --help, -h               Print this help.");
  LOGN(stdout, "  --log, -l        <file>  Log into a file.");
  LOGN(stdout, "  --trace, -t              Trace syscalls.");
  LOGN(stdout, "  --whitelist, -w  <file>  Whitelist syscalls (one by line).");
  exit(exit_status);
}

static void load_whitelist(const char *path) {
  char buffer[128];
  FILE *file;

  if((file = fopen(path, "r")) == NULL) {
    LOG_ERR(stderr, "Failed to open %s", path);
  }

  while(fgets(buffer, sizeof buffer, file) != NULL) {
    buffer[strcspn(buffer, "\n")] = '\0';
    if(buffer[0] != '\0') {
      if(!syscall_allow(buffer)) {
        LOG_ERRX(stderr, "Can't whitelist syscall %s", buffer);
      }
    }
  }
  fclose(file);
}

static void parse_options(struct sandbox *sandb, int argc, char **argv) {
  int opt;
  struct option opts[] = {
    {"help",      no_argument,       NULL, 'h'},
    {"log",       required_argument, NULL, 'l'},
    {"trace",     no_argument,       NULL, 't'},
    {"whitelist", required_argument, NULL, 'w'},
    {NULL,        0,                 NULL, 0}
  };

  while((opt = getopt_long(argc, argv, "+hl:tw:", opts, NULL)) > 0) {
    switch(opt) {
    case 'h':
      usage(argv[0], EXIT_SUCCESS);
      break;
    case 'l':
      sandb->log = fopen(optarg, "a");
      if(sandb->log == NULL)
        LOG_ERR(stderr, "Failed to open %s", optarg);
      break;
    case 't':
      sandb->trace = true;
      break;
    case 'w':
      load_whitelist(optarg);
      break;
    default:
      usage(argv[0], EXIT_FAILURE);
      break;
    }
  }

  if(optind == argc) {
    usage(argv[0], EXIT_FAILURE);
  }

  sandb->argc = argc - optind;
  sandb->argv = argv + optind;
}

int main(int argc, char **argv) {
  struct sandbox sandb;

  syscalls_init();
  handlers_init();
  sandbox_init(&sandb);
  parse_options(&sandb, argc, argv);

  sandbox_run(&sandb);

  return EXIT_SUCCESS;
}
