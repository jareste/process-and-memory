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
#include <linux/slab.h>

struct pid_info {
    int                 pid;
    int                 state;
    void*               stack_ptr;
    unsigned long       age;
    struct timespec64   time;
    size_t              nb_childs;
    pid_t               *child_pids;
    size_t              childs_len;
    pid_t               parent_pid;
    char                *exe;
    char                *root_path;
    char                *pwd;
};

static int fetch_path(char * __user dst, size_t len, struct path *path)
{
    char *buffer;
    char *resolved_path;
    int ret = 0;

    buffer = kmalloc(len, GFP_KERNEL);
    if (!buffer)
        return -ENOMEM;

    resolved_path = d_path(path, buffer, len);
    if (IS_ERR(resolved_path))
    {
        ret = PTR_ERR(resolved_path);
    }
    else if (len < strlen(resolved_path))
    {
        ret = -ENOMEM;
    }
    else if (copy_to_user(dst, resolved_path, strlen(resolved_path)))
    {
        ret = -EFAULT;
    }

    kfree(buffer);
    return ret;
}

int get_pwd(char * __user dst, size_t len, struct task_struct *tsk)
{
    struct path pwd;
    get_fs_pwd(tsk->fs, &pwd);
    return fetch_path(dst, len, &pwd);
}

int get_root(char * __user dst, size_t len, struct task_struct *tsk)
{
    struct path root;
    get_fs_root(tsk->fs, &root);
    return fetch_path(dst, len, &root);
}

int get_exe(char * __user dst, size_t len, struct task_struct *tsk)
{
    char *buffer;
    char *path;
    struct file *exe_file;
    int ret = 0;

    buffer = kmalloc(len, GFP_KERNEL);
    if (!buffer)
        return -ENOMEM;

    exe_file = get_task_exe_file(tsk);
    if (!exe_file)
    {
        if (copy_to_user(dst, "[", 1) ||
            copy_to_user(dst + 1, tsk->comm, strlen(tsk->comm)) ||
            copy_to_user(dst + strlen(tsk->comm) + 1, "]", 1))
        {
            ret = -EFAULT;
        }
        kfree(buffer);
        return ret;
    }

    path_get(&exe_file->f_path);
    path = file_path(exe_file, buffer, len);
    if (IS_ERR(path))
    {
        ret = PTR_ERR(path);
    }
    else if (len < strlen(path))
    {
        ret = -ENOMEM;
    }
    else if (copy_to_user(dst, path, strlen(path)))
    {
        ret = -EFAULT;
    }

    path_put(&exe_file->f_path);
    kfree(buffer);
    return ret;
}

SYSCALL_DEFINE2(get_pid_info, struct pid_info __user *, user_ret, int, pid)
{
    struct task_struct *task;
    struct task_struct *child;
    struct pid_info info = {0};
    struct path root_path, pwd_path;
    pid_t *tmp;

    rcu_read_lock();

    if (copy_from_user(&info, user_ret, sizeof(info)))
    {
        rcu_read_unlock();
        return -EFAULT;
    }

    task = find_task_by_vpid(pid);
    if (!task)
    {
        rcu_read_unlock();
        return -ESRCH;
    }

    info.pid = task->pid;

    info.state = task_state_to_char(task);
    info.time = ns_to_timespec64(ktime_get_ns() - task->start_time);

    info.stack_ptr = task->stack;
    info.age = jiffies_to_msecs(jiffies - task->start_time);
    info.parent_pid = task->parent->pid;

    get_fs_root(task->fs, &root_path);
    get_fs_pwd(task->fs, &pwd_path);

    if (!dentry_path_raw(root_path.dentry, info.root_path, sizeof(info.root_path)))
        strncpy(info.root_path, "(unknown)", sizeof(info.root_path));

    if (!dentry_path_raw(pwd_path.dentry, info.pwd, sizeof(info.pwd)))
        strncpy(info.pwd, "(unknown)", sizeof(info.pwd));

    /* Childs */
    list_for_each_entry(child, &task->children, sibling)
    {
        info.nb_childs++;
    }

    if (info.nb_childs * sizeof(pid_t) > info.childs_len)
        return (-ENOMEM);

    if (info.nb_childs)
    {
        tmp = info.nb_childs;
        list_for_each_entry(child, &task->children, sibling)
        {
            *tmp = child->pid;
            if (copy_to_user(tmp, &child->pid, sizeof(pid_t)))
                return (-EFAULT);
            tmp += 1;
        }
    }
    /* Childs END */
    rcu_read_unlock();

    if (copy_to_user(user_ret, &info, sizeof(info)))
        return -EFAULT;

    if (user_ret->exe)
    {
        if (get_exe(user_ret->exe, PATH_MAX, task))
            return -EFAULT;
    }

    if (user_ret->root_path)
    {
        if (get_root(user_ret->root_path, PATH_MAX, task))
            return -EFAULT;
    }

    if (user_ret->pwd)
    {
        if (get_pwd(user_ret->pwd, PATH_MAX, task))
            return -EFAULT;
    }

    return 0;
}
