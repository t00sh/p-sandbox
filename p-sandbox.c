/*
 * Run program and blacklist its syscalls.
 *
 * Compilation 32bits :
 * gcc -m32 -Wall -fstack-protector-all -O2 sandbox.c -o sandbox
 *
 * Compilation 64bits:
 * gcc -m64 -Wall -fstack-protector-all -O2 sandbox.c -o sandbox
 */

#include <sys/ptrace.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <err.h>
#include <sys/user.h>
#include <asm/ptrace.h>
#include <sys/wait.h>
#include <asm/unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/syscall.h>

#define SYSCALLS 512

#define BLACKLIST_SYSCALL(s) do { \
    syscalls_blacklist[s] = 1;	  \
    syscalls_strings[s] = #s;	  \
  } while(0)

struct sandbox {
  pid_t child;
  const char *progname;
};

static unsigned char syscalls_blacklist[SYSCALLS] = {0};
static const char *syscalls_strings[SYSCALLS] = {NULL};

static void sandb_kill(struct sandbox *sandb) {
  kill(sandb->child, SIGKILL);
  wait(NULL);
  exit(EXIT_FAILURE);
}

#ifdef __x86_64__
#define GET_AX_REG(regs) ((regs).orig_rax)
#else
#define GET_AX_REG(regs) ((regs).orig_eax)
#endif

static void sandb_handle_syscall(struct sandbox *sandb) {
  struct user_regs_struct regs;

  if(ptrace(PTRACE_GETREGS, sandb->child, NULL, &regs) < 0)
    err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_GETREGS:");

  if(GET_AX_REG(regs) < 0 ||
     GET_AX_REG(regs) >= SYSCALLS ||
     syscalls_blacklist[GET_AX_REG(regs)]) {
    if(GET_AX_REG(regs) == -1) {
      printf("[SANDBOX] Segfault ?! KILLING !!!\n");
    } else {
      printf("[SANDBOX] Trying to use blacklisted syscall (%s) "
	     "?!? KILLING !!!\n", syscalls_strings[GET_AX_REG(regs)]);
    }
    sandb_kill(sandb);
  }
}

static void sandb_init(struct sandbox *sandb, int argc, char **argv) {
  pid_t pid;

  pid = fork();

  if(pid == -1)
    err(EXIT_FAILURE, "[SANDBOX] Error on fork:");

  if(pid == 0) {

    if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
      err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_TRACEME:");

    execv(argv[0], argv);
    err(EXIT_FAILURE, "[SANDBOX] Failed to execv:");
  } else {
    sandb->child = pid;
    sandb->progname = argv[0];
    wait(NULL);
  }
}

static void sandb_run(struct sandbox *sandb) {
  int status;

  if(ptrace(PTRACE_SYSCALL, sandb->child, NULL, NULL) < 0) {
    if(errno == ESRCH) {
      waitpid(sandb->child, &status, __WALL | WNOHANG);
      sandb_kill(sandb);
    } else {
      err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_SYSCALL:");
    }
  }

  wait(&status);

  if(WIFEXITED(status))
    exit(EXIT_SUCCESS);

  if(WIFSTOPPED(status)) {
    sandb_handle_syscall(sandb);
  }
}

/*
 * Add or remove syscalls from this list.
 * Some syscalls are needed to run the target program correctly.
 */
static void init_blacklist(void) {
  BLACKLIST_SYSCALL(__NR_execve);
  BLACKLIST_SYSCALL(__NR_fork);
  BLACKLIST_SYSCALL(__NR_vfork);
  BLACKLIST_SYSCALL(__NR_clone);
  BLACKLIST_SYSCALL(__NR_rt_sigreturn);
  BLACKLIST_SYSCALL(__NR_dup2);
  BLACKLIST_SYSCALL(__NR_socket);
  BLACKLIST_SYSCALL(__NR_kill);
  BLACKLIST_SYSCALL(__NR_unlink);
  BLACKLIST_SYSCALL(__NR_chmod);
  BLACKLIST_SYSCALL(__NR_chown);
  BLACKLIST_SYSCALL(__NR_ptrace);
  BLACKLIST_SYSCALL(__NR_setuid);
  BLACKLIST_SYSCALL(__NR_mount);
}

int main(int argc, char **argv) {
  struct sandbox sandb;

  if(argc < 2) {
    errx(EXIT_FAILURE, "[SANDBOX] Usage : %s <elf> [<arg1...>]", argv[0]);
  }

  init_blacklist();
  sandb_init(&sandb, argc-1, argv+1);

  for(;;) {
    sandb_run(&sandb);
  }

  return EXIT_SUCCESS;
}
