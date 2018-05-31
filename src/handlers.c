#include <sys/syscall.h>
#include "log.h"
#include "sandbox.h"
#include "syscalls.h"

static void write_handler(struct sandbox *sandb,
                          struct user_regs_struct *regs) {

  size_t length = GET_ARG3_REG(regs);
  long address = GET_ARG2_REG(regs);
  int fd = GET_ARG1_REG(regs);

  LOGN(sandb->log, "fd=%d, length=%zu", fd, length);
  sandbox_dump_address(sandb, address, length);
}

static void sendto_handler(struct sandbox *sandb,
                           struct user_regs_struct *regs) {

  size_t length = GET_ARG3_REG(regs);
  long address = GET_ARG2_REG(regs);

  sandbox_dump_address(sandb, address, length);
}

void handlers_init(void) {
  syscall_add_handler(__NR_write, write_handler);
  syscall_add_handler(__NR_sendto, sendto_handler);
}
