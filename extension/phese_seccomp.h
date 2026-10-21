/* SPDX-License-Identifier: MIT */
#ifndef PHESE_SECCOMP_H
#define PHESE_SECCOMP_H

#if !defined(__linux__)
#error "phese requires Linux seccomp"
#endif

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__x86_64__) && !defined(__ILP32__)
#define PHESE_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define PHESE_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#error "phese supports only Linux x86_64 (LP64) and aarch64"
#endif

#define PHESE_ERRNO(error) (SECCOMP_RET_ERRNO | ((error) & SECCOMP_RET_DATA))
#define PHESE_DENY(nr) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr), 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, PHESE_ERRNO(EPERM))

/* No allocation and no external library dependencies: safe at PHP MINIT. */
static int phese_install_filter(void)
{
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PHESE_AUDIT_ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
#if defined(__x86_64__)
        /* Reject x32, whose syscall numbers otherwise bypass an LP64 deny list. */
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x40000000U, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, PHESE_ERRNO(EPERM)),
#endif
#ifdef __NR_execve
        PHESE_DENY(__NR_execve),
#endif
#ifdef __NR_execveat
        PHESE_DENY(__NR_execveat),
#endif
#ifdef __NR_ptrace
        PHESE_DENY(__NR_ptrace),
#endif
#ifdef __NR_process_vm_readv
        PHESE_DENY(__NR_process_vm_readv),
#endif
#ifdef __NR_process_vm_writev
        PHESE_DENY(__NR_process_vm_writev),
#endif
#ifdef __NR_pidfd_getfd
        PHESE_DENY(__NR_pidfd_getfd),
#endif
#ifdef __NR_mount
        PHESE_DENY(__NR_mount),
#endif
#ifdef __NR_umount2
        PHESE_DENY(__NR_umount2),
#endif
#ifdef __NR_pivot_root
        PHESE_DENY(__NR_pivot_root),
#endif
#ifdef __NR_chroot
        PHESE_DENY(__NR_chroot),
#endif
#ifdef __NR_unshare
        PHESE_DENY(__NR_unshare),
#endif
#ifdef __NR_setns
        PHESE_DENY(__NR_setns),
#endif
#ifdef __NR_open_tree
        PHESE_DENY(__NR_open_tree),
#endif
#ifdef __NR_move_mount
        PHESE_DENY(__NR_move_mount),
#endif
#ifdef __NR_fsopen
        PHESE_DENY(__NR_fsopen),
#endif
#ifdef __NR_fsconfig
        PHESE_DENY(__NR_fsconfig),
#endif
#ifdef __NR_fsmount
        PHESE_DENY(__NR_fsmount),
#endif
#ifdef __NR_fspick
        PHESE_DENY(__NR_fspick),
#endif
#ifdef __NR_mount_setattr
        PHESE_DENY(__NR_mount_setattr),
#endif
#ifdef __NR_open_by_handle_at
        PHESE_DENY(__NR_open_by_handle_at),
#endif
#ifdef __NR_name_to_handle_at
        PHESE_DENY(__NR_name_to_handle_at),
#endif
#ifdef __NR_bpf
        PHESE_DENY(__NR_bpf),
#endif
#ifdef __NR_perf_event_open
        PHESE_DENY(__NR_perf_event_open),
#endif
#ifdef __NR_userfaultfd
        PHESE_DENY(__NR_userfaultfd),
#endif
#ifdef __NR_keyctl
        PHESE_DENY(__NR_keyctl),
#endif
#ifdef __NR_add_key
        PHESE_DENY(__NR_add_key),
#endif
#ifdef __NR_request_key
        PHESE_DENY(__NR_request_key),
#endif
#ifdef __NR_io_uring_setup
        PHESE_DENY(__NR_io_uring_setup),
#endif
#ifdef __NR_io_uring_enter
        PHESE_DENY(__NR_io_uring_enter),
#endif
#ifdef __NR_io_uring_register
        PHESE_DENY(__NR_io_uring_register),
#endif
#ifdef __NR_init_module
        PHESE_DENY(__NR_init_module),
#endif
#ifdef __NR_finit_module
        PHESE_DENY(__NR_finit_module),
#endif
#ifdef __NR_delete_module
        PHESE_DENY(__NR_delete_module),
#endif
#ifdef __NR_kexec_load
        PHESE_DENY(__NR_kexec_load),
#endif
#ifdef __NR_kexec_file_load
        PHESE_DENY(__NR_kexec_file_load),
#endif
#ifdef __NR_reboot
        PHESE_DENY(__NR_reboot),
#endif
#ifdef __NR_swapon
        PHESE_DENY(__NR_swapon),
#endif
#ifdef __NR_swapoff
        PHESE_DENY(__NR_swapoff),
#endif
#ifdef __NR_iopl
        PHESE_DENY(__NR_iopl),
#endif
#ifdef __NR_ioperm
        PHESE_DENY(__NR_ioperm),
#endif
#ifdef __NR_acct
        PHESE_DENY(__NR_acct),
#endif
#ifdef __NR_quotactl
        PHESE_DENY(__NR_quotactl),
#endif
#ifdef __NR_settimeofday
        PHESE_DENY(__NR_settimeofday),
#endif
#ifdef __NR_clock_settime
        PHESE_DENY(__NR_clock_settime),
#endif
#ifdef __NR_adjtimex
        PHESE_DENY(__NR_adjtimex),
#endif
#ifdef __NR_clock_adjtime
        PHESE_DENY(__NR_clock_adjtime),
#endif
#ifdef __NR_clone3
        /* glibc falls back to clone only on ENOSYS, not EPERM. */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone3, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, PHESE_ERRNO(ENOSYS)),
#endif
#ifdef __NR_clone
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x7e020000U, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, PHESE_ERRNO(EPERM)),
#endif
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        return -1;
    }
    /* Synchronize pre-existing threads; fail closed if the kernel cannot do so. */
    long result = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                          SECCOMP_FILTER_FLAG_TSYNC, &program);
    if (result != 0) {
        if (result > 0) {
            errno = EBUSY; /* TSYNC can return the unsynchronizable thread ID. */
        }
        return -1;
    }
    return 0;
}

#undef PHESE_DENY
#endif
