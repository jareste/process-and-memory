#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/uaccess.h>
#include <linux/mm.h>

SYSCALL_DEFINE0(ft_fork)
{
    struct kernel_clone_args args = {
        .flags = SIGCHLD,
        .exit_signal = SIGCHLD,
    };

    pid_t pid = kernel_clone(&args);

    if (pid < 0)
        return pid;

    return pid;
}
