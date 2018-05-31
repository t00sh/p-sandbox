#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>

#include "syscalls.h"

static struct syscall syscalls[SYSCALLS];

#define SYSCALL_INIT(s) do {                             \
  syscalls[s].string  = #s;                              \
  syscalls[s].handler = NULL;                            \
  syscalls[s].allowed = false;                           \
  } while(0)

bool syscall_is_allowed(int syscall) {
  assert(syscall >= 0 && syscall < SYSCALLS);
  return syscalls[syscall].allowed;
}

const char *syscall_string(int syscall) {
  assert(syscall >= 0 && syscall < SYSCALLS);
  return syscalls[syscall].string + 5;
}

int syscall_allow(const char *string) {
  int i;

  for(i = 0; i < SYSCALLS; i++) {
    if(syscalls[i].string != NULL) {
      if(!strcmp(syscall_string(i), string)) {
        syscalls[i].allowed = true;
        return 1;
      }
    }
  }
  return 0;
}

void syscall_add_handler(int syscall, syscall_handler handler) {
  assert(syscall >= 0 && syscall < SYSCALLS);
  syscalls[syscall].handler = handler;
}

void syscall_exec_handler(int syscall, struct sandbox *sandb,
                          struct user_regs_struct *regs) {
  assert(syscall >= 0 && syscall < SYSCALLS);
  if(syscalls[syscall].handler) {
    syscalls[syscall].handler(sandb, regs);
  }
}

void syscalls_init(void) {
  SYSCALL_INIT(__NR_read);
  SYSCALL_INIT(__NR_write);
  SYSCALL_INIT(__NR_open);
  SYSCALL_INIT(__NR_close);
  SYSCALL_INIT(__NR_stat);
  SYSCALL_INIT(__NR_fstat);
  SYSCALL_INIT(__NR_lstat);
  SYSCALL_INIT(__NR_poll);
  SYSCALL_INIT(__NR_lseek);
  SYSCALL_INIT(__NR_mmap);
  SYSCALL_INIT(__NR_mprotect);
  SYSCALL_INIT(__NR_munmap);
  SYSCALL_INIT(__NR_brk);
  SYSCALL_INIT(__NR_rt_sigaction);
  SYSCALL_INIT(__NR_rt_sigprocmask);
  SYSCALL_INIT(__NR_rt_sigreturn);
  SYSCALL_INIT(__NR_ioctl);
  SYSCALL_INIT(__NR_pread64);
  SYSCALL_INIT(__NR_pwrite64);
  SYSCALL_INIT(__NR_readv);
  SYSCALL_INIT(__NR_writev);
  SYSCALL_INIT(__NR_access);
  SYSCALL_INIT(__NR_pipe);
  SYSCALL_INIT(__NR_select);
  SYSCALL_INIT(__NR_sched_yield);
  SYSCALL_INIT(__NR_mremap);
  SYSCALL_INIT(__NR_msync);
  SYSCALL_INIT(__NR_mincore);
  SYSCALL_INIT(__NR_madvise);
  SYSCALL_INIT(__NR_shmget);
  SYSCALL_INIT(__NR_shmat);
  SYSCALL_INIT(__NR_shmctl);
  SYSCALL_INIT(__NR_dup);
  SYSCALL_INIT(__NR_dup2);
  SYSCALL_INIT(__NR_pause);
  SYSCALL_INIT(__NR_nanosleep);
  SYSCALL_INIT(__NR_getitimer);
  SYSCALL_INIT(__NR_alarm);
  SYSCALL_INIT(__NR_setitimer);
  SYSCALL_INIT(__NR_getpid);
  SYSCALL_INIT(__NR_sendfile);
  SYSCALL_INIT(__NR_socket);
  SYSCALL_INIT(__NR_connect);
  SYSCALL_INIT(__NR_accept);
  SYSCALL_INIT(__NR_sendto);
  SYSCALL_INIT(__NR_recvfrom);
  SYSCALL_INIT(__NR_sendmsg);
  SYSCALL_INIT(__NR_recvmsg);
  SYSCALL_INIT(__NR_shutdown);
  SYSCALL_INIT(__NR_bind);
  SYSCALL_INIT(__NR_listen);
  SYSCALL_INIT(__NR_getsockname);
  SYSCALL_INIT(__NR_getpeername);
  SYSCALL_INIT(__NR_socketpair);
  SYSCALL_INIT(__NR_setsockopt);
  SYSCALL_INIT(__NR_getsockopt);
  SYSCALL_INIT(__NR_clone);
  SYSCALL_INIT(__NR_fork);
  SYSCALL_INIT(__NR_vfork);
  SYSCALL_INIT(__NR_execve);
  SYSCALL_INIT(__NR_exit);
  SYSCALL_INIT(__NR_wait4);
  SYSCALL_INIT(__NR_kill);
  SYSCALL_INIT(__NR_uname);
  SYSCALL_INIT(__NR_semget);
  SYSCALL_INIT(__NR_semop);
  SYSCALL_INIT(__NR_semctl);
  SYSCALL_INIT(__NR_shmdt);
  SYSCALL_INIT(__NR_msgget);
  SYSCALL_INIT(__NR_msgsnd);
  SYSCALL_INIT(__NR_msgrcv);
  SYSCALL_INIT(__NR_msgctl);
  SYSCALL_INIT(__NR_fcntl);
  SYSCALL_INIT(__NR_flock);
  SYSCALL_INIT(__NR_fsync);
  SYSCALL_INIT(__NR_fdatasync);
  SYSCALL_INIT(__NR_truncate);
  SYSCALL_INIT(__NR_ftruncate);
  SYSCALL_INIT(__NR_getdents);
  SYSCALL_INIT(__NR_getcwd);
  SYSCALL_INIT(__NR_chdir);
  SYSCALL_INIT(__NR_fchdir);
  SYSCALL_INIT(__NR_rename);
  SYSCALL_INIT(__NR_mkdir);
  SYSCALL_INIT(__NR_rmdir);
  SYSCALL_INIT(__NR_creat);
  SYSCALL_INIT(__NR_link);
  SYSCALL_INIT(__NR_unlink);
  SYSCALL_INIT(__NR_symlink);
  SYSCALL_INIT(__NR_readlink);
  SYSCALL_INIT(__NR_chmod);
  SYSCALL_INIT(__NR_fchmod);
  SYSCALL_INIT(__NR_chown);
  SYSCALL_INIT(__NR_fchown);
  SYSCALL_INIT(__NR_lchown);
  SYSCALL_INIT(__NR_umask);
  SYSCALL_INIT(__NR_gettimeofday);
  SYSCALL_INIT(__NR_getrlimit);
  SYSCALL_INIT(__NR_getrusage);
  SYSCALL_INIT(__NR_sysinfo);
  SYSCALL_INIT(__NR_times);
  SYSCALL_INIT(__NR_ptrace);
  SYSCALL_INIT(__NR_getuid);
  SYSCALL_INIT(__NR_syslog);
  SYSCALL_INIT(__NR_getgid);
  SYSCALL_INIT(__NR_setuid);
  SYSCALL_INIT(__NR_setgid);
  SYSCALL_INIT(__NR_geteuid);
  SYSCALL_INIT(__NR_getegid);
  SYSCALL_INIT(__NR_setpgid);
  SYSCALL_INIT(__NR_getppid);
  SYSCALL_INIT(__NR_getpgrp);
  SYSCALL_INIT(__NR_setsid);
  SYSCALL_INIT(__NR_setreuid);
  SYSCALL_INIT(__NR_setregid);
  SYSCALL_INIT(__NR_getgroups);
  SYSCALL_INIT(__NR_setgroups);
  SYSCALL_INIT(__NR_setresuid);
  SYSCALL_INIT(__NR_getresuid);
  SYSCALL_INIT(__NR_setresgid);
  SYSCALL_INIT(__NR_getresgid);
  SYSCALL_INIT(__NR_getpgid);
  SYSCALL_INIT(__NR_setfsuid);
  SYSCALL_INIT(__NR_setfsgid);
  SYSCALL_INIT(__NR_getsid);
  SYSCALL_INIT(__NR_capget);
  SYSCALL_INIT(__NR_capset);
  SYSCALL_INIT(__NR_rt_sigpending);
  SYSCALL_INIT(__NR_rt_sigtimedwait);
  SYSCALL_INIT(__NR_rt_sigqueueinfo);
  SYSCALL_INIT(__NR_rt_sigsuspend);
  SYSCALL_INIT(__NR_sigaltstack);
  SYSCALL_INIT(__NR_utime);
  SYSCALL_INIT(__NR_mknod);
  SYSCALL_INIT(__NR_uselib);
  SYSCALL_INIT(__NR_personality);
  SYSCALL_INIT(__NR_ustat);
  SYSCALL_INIT(__NR_statfs);
  SYSCALL_INIT(__NR_fstatfs);
  SYSCALL_INIT(__NR_sysfs);
  SYSCALL_INIT(__NR_getpriority);
  SYSCALL_INIT(__NR_setpriority);
  SYSCALL_INIT(__NR_sched_setparam);
  SYSCALL_INIT(__NR_sched_getparam);
  SYSCALL_INIT(__NR_sched_setscheduler);
  SYSCALL_INIT(__NR_sched_getscheduler);
  SYSCALL_INIT(__NR_sched_get_priority_max);
  SYSCALL_INIT(__NR_sched_get_priority_min);
  SYSCALL_INIT(__NR_sched_rr_get_interval);
  SYSCALL_INIT(__NR_mlock);
  SYSCALL_INIT(__NR_munlock);
  SYSCALL_INIT(__NR_mlockall);
  SYSCALL_INIT(__NR_munlockall);
  SYSCALL_INIT(__NR_vhangup);
  SYSCALL_INIT(__NR_modify_ldt);
  SYSCALL_INIT(__NR_pivot_root);
  SYSCALL_INIT(__NR__sysctl);
  SYSCALL_INIT(__NR_prctl);
  SYSCALL_INIT(__NR_arch_prctl);
  SYSCALL_INIT(__NR_adjtimex);
  SYSCALL_INIT(__NR_setrlimit);
  SYSCALL_INIT(__NR_chroot);
  SYSCALL_INIT(__NR_sync);
  SYSCALL_INIT(__NR_acct);
  SYSCALL_INIT(__NR_settimeofday);
  SYSCALL_INIT(__NR_mount);
  SYSCALL_INIT(__NR_umount2);
  SYSCALL_INIT(__NR_swapon);
  SYSCALL_INIT(__NR_swapoff);
  SYSCALL_INIT(__NR_reboot);
  SYSCALL_INIT(__NR_sethostname);
  SYSCALL_INIT(__NR_setdomainname);
  SYSCALL_INIT(__NR_iopl);
  SYSCALL_INIT(__NR_ioperm);
  SYSCALL_INIT(__NR_create_module);
  SYSCALL_INIT(__NR_init_module);
  SYSCALL_INIT(__NR_delete_module);
  SYSCALL_INIT(__NR_get_kernel_syms);
  SYSCALL_INIT(__NR_query_module);
  SYSCALL_INIT(__NR_quotactl);
  SYSCALL_INIT(__NR_nfsservctl);
  SYSCALL_INIT(__NR_getpmsg);
  SYSCALL_INIT(__NR_putpmsg);
  SYSCALL_INIT(__NR_afs_syscall);
  SYSCALL_INIT(__NR_tuxcall);
  SYSCALL_INIT(__NR_security);
  SYSCALL_INIT(__NR_gettid);
  SYSCALL_INIT(__NR_readahead);
  SYSCALL_INIT(__NR_setxattr);
  SYSCALL_INIT(__NR_lsetxattr);
  SYSCALL_INIT(__NR_fsetxattr);
  SYSCALL_INIT(__NR_getxattr);
  SYSCALL_INIT(__NR_lgetxattr);
  SYSCALL_INIT(__NR_fgetxattr);
  SYSCALL_INIT(__NR_listxattr);
  SYSCALL_INIT(__NR_llistxattr);
  SYSCALL_INIT(__NR_flistxattr);
  SYSCALL_INIT(__NR_removexattr);
  SYSCALL_INIT(__NR_lremovexattr);
  SYSCALL_INIT(__NR_fremovexattr);
  SYSCALL_INIT(__NR_tkill);
  SYSCALL_INIT(__NR_time);
  SYSCALL_INIT(__NR_futex);
  SYSCALL_INIT(__NR_sched_setaffinity);
  SYSCALL_INIT(__NR_sched_getaffinity);
  SYSCALL_INIT(__NR_set_thread_area);
  SYSCALL_INIT(__NR_io_setup);
  SYSCALL_INIT(__NR_io_destroy);
  SYSCALL_INIT(__NR_io_getevents);
  SYSCALL_INIT(__NR_io_submit);
  SYSCALL_INIT(__NR_io_cancel);
  SYSCALL_INIT(__NR_get_thread_area);
  SYSCALL_INIT(__NR_lookup_dcookie);
  SYSCALL_INIT(__NR_epoll_create);
  SYSCALL_INIT(__NR_epoll_ctl_old);
  SYSCALL_INIT(__NR_epoll_wait_old);
  SYSCALL_INIT(__NR_remap_file_pages);
  SYSCALL_INIT(__NR_getdents64);
  SYSCALL_INIT(__NR_set_tid_address);
  SYSCALL_INIT(__NR_restart_syscall);
  SYSCALL_INIT(__NR_semtimedop);
  SYSCALL_INIT(__NR_fadvise64);
  SYSCALL_INIT(__NR_timer_create);
  SYSCALL_INIT(__NR_timer_settime);
  SYSCALL_INIT(__NR_timer_gettime);
  SYSCALL_INIT(__NR_timer_getoverrun);
  SYSCALL_INIT(__NR_timer_delete);
  SYSCALL_INIT(__NR_clock_settime);
  SYSCALL_INIT(__NR_clock_gettime);
  SYSCALL_INIT(__NR_clock_getres);
  SYSCALL_INIT(__NR_clock_nanosleep);
  SYSCALL_INIT(__NR_exit_group);
  SYSCALL_INIT(__NR_epoll_wait);
  SYSCALL_INIT(__NR_epoll_ctl);
  SYSCALL_INIT(__NR_tgkill);
  SYSCALL_INIT(__NR_utimes);
  SYSCALL_INIT(__NR_vserver);
  SYSCALL_INIT(__NR_mbind);
  SYSCALL_INIT(__NR_set_mempolicy);
  SYSCALL_INIT(__NR_get_mempolicy);
  SYSCALL_INIT(__NR_mq_open);
  SYSCALL_INIT(__NR_mq_unlink);
  SYSCALL_INIT(__NR_mq_timedsend);
  SYSCALL_INIT(__NR_mq_timedreceive);
  SYSCALL_INIT(__NR_mq_notify);
  SYSCALL_INIT(__NR_mq_getsetattr);
  SYSCALL_INIT(__NR_kexec_load);
  SYSCALL_INIT(__NR_waitid);
  SYSCALL_INIT(__NR_add_key);
  SYSCALL_INIT(__NR_request_key);
  SYSCALL_INIT(__NR_keyctl);
  SYSCALL_INIT(__NR_ioprio_set);
  SYSCALL_INIT(__NR_ioprio_get);
  SYSCALL_INIT(__NR_inotify_init);
  SYSCALL_INIT(__NR_inotify_add_watch);
  SYSCALL_INIT(__NR_inotify_rm_watch);
  SYSCALL_INIT(__NR_migrate_pages);
  SYSCALL_INIT(__NR_openat);
  SYSCALL_INIT(__NR_mkdirat);
  SYSCALL_INIT(__NR_mknodat);
  SYSCALL_INIT(__NR_fchownat);
  SYSCALL_INIT(__NR_futimesat);
  SYSCALL_INIT(__NR_newfstatat);
  SYSCALL_INIT(__NR_unlinkat);
  SYSCALL_INIT(__NR_renameat);
  SYSCALL_INIT(__NR_linkat);
  SYSCALL_INIT(__NR_symlinkat);
  SYSCALL_INIT(__NR_readlinkat);
  SYSCALL_INIT(__NR_fchmodat);
  SYSCALL_INIT(__NR_faccessat);
  SYSCALL_INIT(__NR_pselect6);
  SYSCALL_INIT(__NR_ppoll);
  SYSCALL_INIT(__NR_unshare);
  SYSCALL_INIT(__NR_set_robust_list);
  SYSCALL_INIT(__NR_get_robust_list);
  SYSCALL_INIT(__NR_splice);
  SYSCALL_INIT(__NR_tee);
  SYSCALL_INIT(__NR_sync_file_range);
  SYSCALL_INIT(__NR_vmsplice);
  SYSCALL_INIT(__NR_move_pages);
  SYSCALL_INIT(__NR_utimensat);
  SYSCALL_INIT(__NR_epoll_pwait);
  SYSCALL_INIT(__NR_signalfd);
  SYSCALL_INIT(__NR_timerfd_create);
  SYSCALL_INIT(__NR_eventfd);
  SYSCALL_INIT(__NR_fallocate);
  SYSCALL_INIT(__NR_timerfd_settime);
  SYSCALL_INIT(__NR_timerfd_gettime);
  SYSCALL_INIT(__NR_accept4);
  SYSCALL_INIT(__NR_signalfd4);
  SYSCALL_INIT(__NR_eventfd2);
  SYSCALL_INIT(__NR_epoll_create1);
  SYSCALL_INIT(__NR_dup3);
  SYSCALL_INIT(__NR_pipe2);
  SYSCALL_INIT(__NR_inotify_init1);
  SYSCALL_INIT(__NR_preadv);
  SYSCALL_INIT(__NR_pwritev);
  SYSCALL_INIT(__NR_rt_tgsigqueueinfo);
  SYSCALL_INIT(__NR_perf_event_open);
  SYSCALL_INIT(__NR_recvmmsg);
  SYSCALL_INIT(__NR_fanotify_init);
  SYSCALL_INIT(__NR_fanotify_mark);
  SYSCALL_INIT(__NR_prlimit64);
  SYSCALL_INIT(__NR_name_to_handle_at);
  SYSCALL_INIT(__NR_open_by_handle_at);
  SYSCALL_INIT(__NR_clock_adjtime);
  SYSCALL_INIT(__NR_syncfs);
  SYSCALL_INIT(__NR_sendmmsg);
  SYSCALL_INIT(__NR_setns);
  SYSCALL_INIT(__NR_getcpu);
  SYSCALL_INIT(__NR_process_vm_readv);
  SYSCALL_INIT(__NR_process_vm_writev);
  SYSCALL_INIT(__NR_kcmp);
  SYSCALL_INIT(__NR_finit_module);
  SYSCALL_INIT(__NR_sched_setattr);
  SYSCALL_INIT(__NR_sched_getattr);
  SYSCALL_INIT(__NR_renameat2);
  SYSCALL_INIT(__NR_seccomp);
  SYSCALL_INIT(__NR_getrandom);
  SYSCALL_INIT(__NR_memfd_create);
  SYSCALL_INIT(__NR_kexec_file_load);
  SYSCALL_INIT(__NR_bpf);
  SYSCALL_INIT(__NR_execveat);
  SYSCALL_INIT(__NR_userfaultfd);
  SYSCALL_INIT(__NR_membarrier);
  SYSCALL_INIT(__NR_mlock2);
  SYSCALL_INIT(__NR_copy_file_range);
  SYSCALL_INIT(__NR_preadv2);
  SYSCALL_INIT(__NR_pwritev2);
  SYSCALL_INIT(__NR_pkey_mprotect);
  SYSCALL_INIT(__NR_pkey_alloc);
  SYSCALL_INIT(__NR_pkey_free);
  SYSCALL_INIT(__NR_statx);
}
