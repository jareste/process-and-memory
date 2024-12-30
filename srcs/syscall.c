#include <linux/errno.h>
#include <linux/fs_struct.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/syscalls.h>
#include <linux/time.h>
#include <linux/path.h>
#include <linux/dcache.h>

struct pid_info {
    int pid;
    int state;
    void *stack_ptr;
    unsigned long age;
    int child_pids[64];
    int parent_pid;
    char root_path[256];
    char pwd[256];
};

SYSCALL_DEFINE2(get_pid_info, struct pid_info __user *, user_ret, int, pid)
{
    struct task_struct *task;
    struct pid_info info = {0};
    struct path root_path, pwd_path;
    rcu_read_lock();

    task = find_task_by_vpid(pid);
    if (!task)
    {
        rcu_read_unlock();
        return -ESRCH;
    }

    info.pid = task->pid;

    switch (task->__state)
    {
        case TASK_RUNNING:
            info.state = 0;
            break;
        case TASK_INTERRUPTIBLE:
        case TASK_UNINTERRUPTIBLE:
            info.state = 1;
            break;
        case EXIT_ZOMBIE:
        case EXIT_DEAD:
            info.state = 2;
            break;
        default:
            info.state = -1;
            break;
    }

    info.stack_ptr = task->stack;
    info.age = jiffies_to_msecs(jiffies - task->start_time);
    info.parent_pid = task->real_parent->pid;

    get_fs_root(task->fs, &root_path);
    get_fs_pwd(task->fs, &pwd_path);
    if (!dentry_path_raw(root_path.dentry, info.root_path, sizeof(info.root_path)) ||
        !dentry_path_raw(pwd_path.dentry, info.pwd, sizeof(info.pwd)))
    {
        rcu_read_unlock();
        return -EFAULT;
    }

    struct list_head *child;
    int i = 0;
    list_for_each(child, &task->children)
    {
        if (i < 64) {
            struct task_struct *child_task = list_entry(child, struct task_struct, sibling);
            info.child_pids[i++] = child_task->pid;
        }
    }
    rcu_read_unlock();

    if (copy_to_user(user_ret, &info, sizeof(info)))
        return -EFAULT;

    return 0;
}
