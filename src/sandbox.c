#define _POSIX_SOURCE
#include <sys/ptrace.h>
#include <errno.h>
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
#include "log.h"

static void sandbox_kill(struct sandbox *sandb) {
  if(sandb->log != stdout && sandb->log != stderr) {
    fclose(sandb->log);
  }
  exit(EXIT_FAILURE);
}

static void sandbox_handle_syscall(struct sandbox *sandb) {
  struct user_regs_struct regs;
  int syscall_reg;

  if(ptrace(PTRACE_GETREGS, sandb->pid, NULL, &regs) < 0)
    LOG_ERR(sandb->log, "Failed to PTRACE_GETREGS");

  syscall_reg = GET_SYSCALL_REG(&regs);

  if(!syscall_is_allowed(syscall_reg)) {
    LOGN(sandb->log, "Trying to use blacklisted syscall (%s) ?!?",
         syscall_string(syscall_reg));
    sandbox_kill(sandb);
  }

  if(sandb->trace) {
    LOGN(sandb->log, "Executing syscall %s...", syscall_string(syscall_reg));
    syscall_exec_handler(syscall_reg, sandb, &regs);
  }
}

static void set_ptrace_opts(struct sandbox *sandb, pid_t pid) {
  if(ptrace(PTRACE_SETOPTIONS, pid, 0,
            PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
            PTRACE_O_TRACECLONE | PTRACE_O_EXITKILL) < 0) {
    LOG_ERR(sandb->log, "Failed to PTRACE_SETOPTIONS");
  }
}

static void sandbox_step(struct sandbox *sandb) {
  int status;

  if(ptrace(PTRACE_SYSCALL, sandb->pid, NULL, NULL) < 0) {
    if(errno == ESRCH) {
      waitpid(sandb->pid, &status, __WALL | WNOHANG);
      if(sandb->pid == sandb->main_pid) {
        sandbox_kill(sandb);
      }
      sandb->pid = wait(NULL);
      return;
    } else {
      LOG_ERR(sandb->log, "Failed to PTRACE_SYSCALL");
    }
  }

  sandb->pid = wait(&status);

  if(WIFEXITED(status) && sandb->pid == sandb->main_pid) {
    sandbox_kill(sandb);
  }

  if(WIFSTOPPED(status)) {
    sandbox_handle_syscall(sandb);

    if(ptrace(PTRACE_SYSCALL, sandb->pid, NULL, NULL) < 0) {
      LOG_ERR(sandb->log, "Failed to PTRACE_SYSCALL");
    }
    sandb->pid = wait(NULL);
  }
}

void sandbox_dump_address(struct sandbox *sandb,
                          long address, size_t length) {
  long word;
  size_t i;
  uint8_t *buffer;

  if((buffer = malloc(length)) == NULL) {
    LOG_ERR(sandb->log, "Failed to allocate buffer");
  }

  for(i = 0; i < length; i += sizeof word) {
    printf("%lx\n", address + i);
    word = ptrace(PTRACE_PEEKDATA, sandb->pid, address + i, NULL);

    if(i + sizeof word > (size_t) length) {
      memcpy(buffer + i, &word, length - i);
    } else {
      memcpy(buffer + i, &word, sizeof word);
    }
  }

  hexdump_buffer(sandb->log, buffer, length);
  free(buffer);
}

void sandbox_init(struct sandbox *sandb) {
  sandb->argv = NULL;
  sandb->argc = 0;
  sandb->trace = false;
  sandb->log = stdout;
  sandb->pid = -1;
  sandb->main_pid = -1;
}

void sandbox_run(struct sandbox *sandb) {

  sandb->pid = fork();
  sandb->main_pid = sandb->pid;

  if(sandb->pid == -1) {
    LOG_ERR(sandb->log, "Error on fork");
  }

  if(sandb->pid == 0) {

    if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
      LOG_ERR(sandb->log, "Failed to PTRACE_TRACEME");
    }

    execv(sandb->argv[0], sandb->argv);
    LOG_ERR(sandb->log, "Failed to execv %s", sandb->argv[0]);
  } else {
    wait(NULL);
  }

  set_ptrace_opts(sandb, sandb->pid);

  for(;;) {
    sandbox_step(sandb);
  }
}
