#define _POSIX_SOURCE
#include <sys/ptrace.h>
#include <errno.h>
#include <err.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>


#include "syscalls.h"
#include "sandbox.h"
#include "utils.h"

static void sandbox_kill(struct sandbox *sandb) {
  if(sandb->log != stdout && sandb->log != stderr) {
    fclose(sandb->log);
  }
  kill(sandb->pid, SIGKILL);
  wait(NULL);
  exit(EXIT_FAILURE);
}

static void sandbox_handle_syscall(struct sandbox *sandb) {
  struct user_regs_struct regs;
  int syscall_reg;

  if(ptrace(PTRACE_GETREGS, sandb->pid, NULL, &regs) < 0)
    err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_GETREGS:");

  syscall_reg = GET_SYSCALL_REG(&regs);

  if(!syscall_is_allowed(syscall_reg)) {
    printf("[SANDBOX] Trying to use blacklisted syscall (%s) "
           "?!? KILLING !!!\n", syscall_string(syscall_reg));
    sandbox_kill(sandb);
  }

  printf("[SANDBOX] Executing syscall %s...\n", syscall_string(syscall_reg));
  syscall_exec_handler(syscall_reg, sandb, &regs);
}

static void sandbox_step(struct sandbox *sandb) {
  int status;

  if(ptrace(PTRACE_SYSCALL, sandb->pid, NULL, NULL) < 0) {
    if(errno == ESRCH) {
      waitpid(sandb->pid, &status, __WALL | WNOHANG);
      sandbox_kill(sandb);
    } else {
      err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_SYSCALL");
    }
  }

  wait(&status);

  if(WIFEXITED(status))
    exit(EXIT_SUCCESS);

  if(WIFSTOPPED(status)) {
    sandbox_handle_syscall(sandb);

    if(ptrace(PTRACE_SYSCALL, sandb->pid, NULL, NULL) < 0) {
      err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_SYSCALL");
    }
    wait(&status);
  }
}

void sandbox_dump_address(struct sandbox *sandb,
                          long address, size_t length) {
  long word;
  size_t i;
  uint8_t *buffer;

  buffer = malloc(length);
  if(buffer == NULL)
    err(EXIT_FAILURE, "[SANDBOX] Failed to allocate buffer:");

  for(i = 0; i < length; i += sizeof word) {
    word = ptrace(PTRACE_PEEKDATA, sandb->pid, address + i, NULL);
    if(word < 0)
      err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_PEEKDATA:");

    if(i + sizeof word > (size_t) length)
      memcpy(buffer + i, &word, length - i);
    else
      memcpy(buffer + i, &word, sizeof word);
  }

  hexdump_buffer(buffer, length);
  free(buffer);
}

void sandbox_init(struct sandbox *sandb) {
  sandb->argv = NULL;
  sandb->argc = 0;
  sandb->trace = false;
  sandb->log = stdout;
  sandb->pid = -1;
}

void sandbox_run(struct sandbox *sandb) {
  sandb->pid = fork();

  if(sandb->pid == -1)
    err(EXIT_FAILURE, "[SANDBOX] Error on fork");

  if(sandb->pid == 0) {

    if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
      err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_TRACEME");

    execv(sandb->argv[0], sandb->argv);
    err(EXIT_FAILURE, "[SANDBOX] Failed to execv");
  } else {
    wait(NULL);
  }

  for(;;) {
    sandbox_step(sandb);
  }
}
