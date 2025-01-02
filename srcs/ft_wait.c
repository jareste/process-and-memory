#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/syscalls.h>

SYSCALL_DEFINE1(ft_wait, int __user *, status)
{
    struct task_struct *child;
    int ret = 0;

    rcu_read_lock();
    list_for_each_entry(child, &current->children, sibling)
    {
        if (child->exit_state == EXIT_ZOMBIE)
        {
            ret = child->pid;
            if (status)
            {
                int encoded_status = (child->exit_code << 8);
                put_user(encoded_status, status);
            }
            release_task(child);
            break;
        }
    }
    rcu_read_unlock();

    return ret ? ret : -ECHILD;
}
