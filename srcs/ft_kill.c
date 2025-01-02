#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched/signal.h>
#include <linux/syscalls.h>
#include <linux/cred.h>
#include <linux/security.h>
#include <linux/signal.h>

SYSCALL_DEFINE2(ft_kill, pid_t, pid, int, sig)
{
    struct task_struct *task;
    struct kernel_siginfo info;
    const struct cred *caller_cred;

    if (sig < 0 || sig >= _NSIG)
        return -EINVAL;

    memset(&info, 0, sizeof(info));
    info.si_signo = sig;

    rcu_read_lock();
    task = find_task_by_vpid(pid);
    if (!task)
    {
        rcu_read_unlock();
        return -ESRCH;
    }

    caller_cred = current_cred();

    if (security_task_kill(task, &info, sig, caller_cred) != 0)
    {
        rcu_read_unlock();
        return -EPERM;
    }

    rcu_read_unlock();
    return send_sig_info(sig, &info, task);
}
