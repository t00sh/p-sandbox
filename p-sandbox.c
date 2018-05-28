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
#include <ctype.h>
#include <stdint.h>
#include <inttypes.h>

#define SYSCALLS 512

#define BLACKLIST_SYSCALL(s) do { \
    syscalls_blacklist[s] = 1;	  \
    syscalls_strings[s] = #s;	  \
  } while(0)

#define CALLBACK_SYSCALL(s,c) do { \
    syscalls_callbacks[s] = c;	   \
    syscalls_strings[s] = #s;	   \
  } while(0)

struct sandbox {
  pid_t child;
  const char *progname;
};

static unsigned char syscalls_blacklist[SYSCALLS] = {0};
static const char *syscalls_strings[SYSCALLS] = {NULL};
static void (*syscalls_callbacks[SYSCALLS])(struct sandbox*,
					    struct user_regs_struct *);

static void sandb_kill(struct sandbox *sandb) {
  kill(sandb->child, SIGKILL);
  wait(NULL);
  exit(EXIT_FAILURE);
}

#ifdef __x86_64__
#define GET_SYSCALL_REG(regs) ((regs)->orig_rax)
#define GET_ARG1_REG(regs) ((regs)->rdi)
#define GET_ARG2_REG(regs) ((regs)->rsi)
#define GET_ARG3_REG(regs) ((regs)->rdx)

typedef unsigned long long int regint;

#else /* x86 */

#define GET_SYSCALL_REG(regs) ((regs)->orig_eax)
#define GET_ARG1_REG(regs) ((regs)->ebx)
#define GET_ARG2_REG(regs) ((regs)->ecx)
#define GET_ARG3_REG(regs) ((regs)->edx)

typedef long int regint;

#endif

static void sandb_dump_buffer(uint8_t *buffer, regint length) {
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

static void sandb_dump_address(struct sandbox *sandb,
			       regint address, regint length) {
  regint word, i;
  uint8_t *buffer;

  buffer = malloc(length);
  if(buffer == NULL)
    err(EXIT_FAILURE, "[SANDBOX] Failed to allocate buffer:");

  for(i = 0; i < length; i += sizeof word) {
    word = ptrace(PTRACE_PEEKDATA, sandb->child, address + i, NULL);
    if(word < 0)
      err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_PEEKDATA:");

    if(i + sizeof word > length)
      memcpy(buffer + i, &word, length - i);
    else
      memcpy(buffer + i, &word, sizeof word);
  }

  sandb_dump_buffer(buffer, length);
  free(buffer);
}

static void sandb_handle_write(struct sandbox *sandb,
			       struct user_regs_struct *regs) {

  regint length = GET_ARG3_REG(regs);
  regint address = GET_ARG2_REG(regs);

  sandb_dump_address(sandb, address, length);
}

static void sandb_handle_sendto(struct sandbox *sandb,
				struct user_regs_struct *regs) {

  regint length = GET_ARG3_REG(regs);
  regint address = GET_ARG2_REG(regs);

  sandb_dump_address(sandb, address, length);
}


static void sandb_handle_syscall(struct sandbox *sandb) {
  struct user_regs_struct regs;
  regint syscall_reg;

  if(ptrace(PTRACE_GETREGS, sandb->child, NULL, &regs) < 0)
    err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_GETREGS:");

  syscall_reg = GET_SYSCALL_REG(&regs);

  if(syscall_reg < 0 ||
     syscall_reg >= SYSCALLS ||
     syscalls_blacklist[syscall_reg]) {
    if(syscall_reg == -1) {
      printf("[SANDBOX] Segfault ?! KILLING !!!\n");
    } else {
      printf("[SANDBOX] Trying to use blacklisted syscall (%s) "
	     "?!? KILLING !!!\n", syscalls_strings[syscall_reg]);
    }

    sandb_kill(sandb);
  }

  if(syscalls_callbacks[syscall_reg] != NULL) {
    printf("[SANDBOX] Tracing %s...\n", syscalls_strings[syscall_reg]);
    syscalls_callbacks[syscall_reg](sandb, &regs);
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

    if(ptrace(PTRACE_SYSCALL, sandb->child, NULL, NULL) < 0) {
      err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_SYSCALL:");
    }
    wait(&status);
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

static void init_callbacks(void) {
  CALLBACK_SYSCALL(__NR_write, sandb_handle_write);
  CALLBACK_SYSCALL(__NR_sendto, sandb_handle_sendto);
}

int main(int argc, char **argv) {
  struct sandbox sandb;

  if(argc < 2) {
    errx(EXIT_FAILURE, "[SANDBOX] Usage : %s <elf> [<arg1...>]", argv[0]);
  }

  init_blacklist();
  init_callbacks();
  sandb_init(&sandb, argc-1, argv+1);

  for(;;) {
    sandb_run(&sandb);
  }

  return EXIT_SUCCESS;
}
