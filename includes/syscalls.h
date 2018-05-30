#ifndef DEF_SYSCALLS_H
#define DEF_SYSCALLS_H

#include <stdbool.h>
#include <sys/user.h>
#include "sandbox.h"

#define SYSCALLS 512

#ifdef __x86_64__
#define GET_SYSCALL_REG(regs) ((regs)->orig_rax)
#define GET_ARG1_REG(regs) ((regs)->rdi)
#define GET_ARG2_REG(regs) ((regs)->rsi)
#define GET_ARG3_REG(regs) ((regs)->rdx)

#else /* x86 */

#define GET_SYSCALL_REG(regs) ((regs)->orig_eax)
#define GET_ARG1_REG(regs) ((regs)->ebx)
#define GET_ARG2_REG(regs) ((regs)->ecx)
#define GET_ARG3_REG(regs) ((regs)->edx)

#endif

typedef void (*syscall_handler)(struct sandbox*, struct user_regs_struct*);

struct syscall {
  const char *string;
  syscall_handler handler;
  bool allowed;
};

bool syscall_is_allowed(int syscall);
const char *syscall_string(int syscall);
void syscalls_init(void);
int syscall_allow(const char *string);
void syscall_add_handler(int syscall, syscall_handler handler);
void syscall_exec_handler(int syscall, struct sandbox *sandb,
                          struct user_regs_struct *regs);


#endif /* DEF_SYSCALLS_H */
