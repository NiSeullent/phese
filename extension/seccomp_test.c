/* SPDX-License-Identifier: MIT */
#define _GNU_SOURCE
#include "phese_seccomp.h"
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

static pthread_barrier_t ready;
static pthread_barrier_t installed;

static int denied_exec(void)
{
    char *args[] = {"true", NULL};
    char *env[] = {NULL};
    errno = 0;
    long result = syscall(__NR_execve, "/usr/bin/true", args, env);
    return result == -1 && errno == EPERM ? 0 : 20;
}

static void *thread_exec(void *unused)
{
    (void)unused;
    pthread_barrier_wait(&ready);
    pthread_barrier_wait(&installed);
    if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) {
        return (void *)(intptr_t)36;
    }
    return (void *)(intptr_t)denied_exec();
}

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    if (strcmp(argv[1], "tsync") == 0) {
        pthread_t worker;
        void *result;
        if (pthread_barrier_init(&ready, NULL, 2) ||
            pthread_barrier_init(&installed, NULL, 2) ||
            pthread_create(&worker, NULL, thread_exec, NULL)) return 3;
        pthread_barrier_wait(&ready);
        if (phese_install_filter()) { perror("seccomp"); exit(4); }
        pthread_barrier_wait(&installed);
        if (pthread_join(worker, &result)) return 5;
        return (int)(intptr_t)result;
    }
    if (phese_install_filter()) { perror("seccomp"); return 4; }
    if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 ||
        prctl(PR_GET_SECCOMP, 0, 0, 0, 0) != SECCOMP_MODE_FILTER) return 6;
    if (strcmp(argv[1], "exec") == 0) return denied_exec();
    if (strcmp(argv[1], "execveat") == 0) {
#ifdef __NR_execveat
        char *args[] = {"true", NULL};
        char *env[] = {NULL};
        errno = 0;
        long result = syscall(__NR_execveat, AT_FDCWD, "/usr/bin/true", args, env, 0);
        return result == -1 && errno == EPERM ? 0 : 21;
#else
        return 77;
#endif
    }
    if (strcmp(argv[1], "ptrace") == 0) {
        errno = 0;
        long result = syscall(__NR_ptrace, 0, 0, 0, 0);
        return result == -1 && errno == EPERM ? 0 : 22;
    }
    if (strcmp(argv[1], "clone3") == 0) {
#ifdef __NR_clone3
        errno = 0;
        long result = syscall(__NR_clone3, NULL, 0);
        return result == -1 && errno == ENOSYS ? 0 : 23;
#else
        return 77;
#endif
    }
    if (strcmp(argv[1], "namespace") == 0) {
#ifdef __NR_unshare
        errno = 0;
        long result = syscall(__NR_unshare, 0);
        return result == -1 && errno == EPERM ? 0 : 24;
#else
        return 77;
#endif
    }
    if (strcmp(argv[1], "clone_namespace") == 0) {
        errno = 0;
        long result = syscall(__NR_clone, 0x10000000U | SIGCHLD, NULL, NULL, NULL, 0);
        return result == -1 && errno == EPERM ? 0 : 25;
    }
    if (strcmp(argv[1], "fork") == 0) {
        pid_t child = fork();
        int status;
        if (child < 0) return 26;
        if (child == 0) _exit(denied_exec());
        if (waitpid(child, &status, 0) != child) return 27;
        return WIFEXITED(status) ? WEXITSTATUS(status) : 28;
    }
    if (strcmp(argv[1], "thread_after") == 0) {
        pthread_t worker;
        void *result;
        if (pthread_barrier_init(&ready, NULL, 1) ||
            pthread_barrier_init(&installed, NULL, 1) ||
            pthread_create(&worker, NULL, thread_exec, NULL)) return 29;
        if (pthread_join(worker, &result)) return 30;
        return (int)(intptr_t)result;
    }
    if (strcmp(argv[1], "x32") == 0) {
#if defined(__x86_64__)
        errno = 0;
        long result = syscall(0x40000000U | __NR_getpid);
        return result == -1 && errno == EPERM ? 0 : 31;
#else
        return 77;
#endif
    }
    if (strcmp(argv[1], "compat_arch") == 0) {
#if defined(__x86_64__)
        long result;
        __asm__ volatile("int $0x80" : "=a"(result) : "a"(20) : "memory");
        (void)result;
        return 32; /* Kernel must kill this process before this instruction. */
#else
        return 77;
#endif
    }
    if (strcmp(argv[1], "ordinary_io") == 0) {
        char path[] = "/tmp/phese-seccomp-XXXXXX";
        char data[4] = {0};
        int fd = mkstemp(path);
        if (fd < 0) return 33;
        unlink(path);
        if (write(fd, "ok", 2) != 2 || lseek(fd, 0, SEEK_SET) != 0 ||
            read(fd, data, 2) != 2 || strcmp(data, "ok") != 0) return 34;
        return close(fd) == 0 ? 0 : 35;
    }
    return 2;
}
