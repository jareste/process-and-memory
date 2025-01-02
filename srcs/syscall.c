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
    pid_t               *child_pids; /* user must allocate this and tell it's len in childs_len */
    size_t              childs_len;
    pid_t               parent_pid;
    char                *exe;
    char                *root_path;
    char                *pwd;
};

static DEFINE_SPINLOCK(pid_info_lock);

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

static int get_pwd(char * __user dst, size_t len, struct task_struct *tsk)
{
    struct path pwd;
    get_fs_pwd(tsk->fs, &pwd);
    return fetch_path(dst, len, &pwd);
}

static int get_root(char * __user dst, size_t len, struct task_struct *tsk)
{
    struct path root;
    get_fs_root(tsk->fs, &root);
    return fetch_path(dst, len, &root);
}

static int get_exe(char * __user dst, size_t len, struct task_struct *tsk)
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

static bool is_kernel_thread(struct task_struct *task)
{
    return !(task->mm);
}

SYSCALL_DEFINE2(get_pid_info, struct pid_info __user *, user_ret, int, pid)
{
    struct task_struct *task;
    struct task_struct *child;
    struct pid_info info;
    pid_t *tmp;

    /* I received a NULL pointer, so it's an error
     */
    if (!user_ret)
        return -EFAULT;

    /* I received a pointer to a struct, but the struct is invalid
     * (all fields are 0 or NULL), so I can't trust the pointer
     * therefore, it's an error.
     */
    if (copy_from_user(&info, user_ret, sizeof(info)))
        return -EFAULT;

    /* I received a pointer to a struct, but the struct is invalid
     * (all fields are 0 or NULL), so I can't trust the pointer
     * therefore, it's an error.
     */
    if (info.pid == 0 && info.state == 0 && info.stack_ptr == NULL &&
        info.age == 0 && info.time.tv_sec == 0 && info.time.tv_nsec == 0 &&
        info.nb_childs == 0 && info.child_pids == NULL && info.childs_len == 0 &&
        info.parent_pid == 0 && info.exe == NULL && info.root_path == NULL &&
        info.pwd == NULL)
    {
        return -EFAULT;
    }

    if (info.childs_len > 0 && !access_ok(info.child_pids, info.childs_len))
        return -EFAULT;
    if (info.exe && !access_ok(info.exe, PATH_MAX))
        return -EFAULT;
    if (info.root_path && !access_ok(info.root_path, PATH_MAX))
        return -EFAULT;
    if (info.pwd && !access_ok(info.pwd, PATH_MAX))
        return -EFAULT;

    rcu_read_lock();
    spin_lock(&pid_info_lock);

    task = find_task_by_vpid(pid);
    if (!task)
    {
        spin_unlock(&pid_info_lock);
        rcu_read_unlock();
        return -ESRCH;
    }

    info.pid = task->pid;
    info.state = task_state_to_char(task);
    info.stack_ptr = task->stack;
    info.age = jiffies_to_msecs(jiffies - task->start_time);
    info.parent_pid = task->real_parent ? task->real_parent->pid : -1;

    if (task->exit_state == EXIT_ZOMBIE)
    {
        info.time.tv_sec = 0;
        info.time.tv_nsec = 0;
        info.nb_childs = 0;

        if (copy_to_user(user_ret, &info, sizeof(info)))
        {
            spin_unlock(&pid_info_lock);
            rcu_read_unlock();
            return -EFAULT;
        }

        spin_unlock(&pid_info_lock);
        rcu_read_unlock();
        return 0;
    }

    if (is_kernel_thread(task))
    {
        info.time.tv_sec = 0;
        info.time.tv_nsec = 0;
        info.nb_childs = 0;

        if (info.exe && copy_to_user(info.exe, "[kernel_thread]", 15))
        {
            spin_unlock(&pid_info_lock);
            rcu_read_unlock();
            return -EFAULT;
        }

        if (info.root_path && copy_to_user(info.root_path, "(none)", 6))
        {
            spin_unlock(&pid_info_lock);
            rcu_read_unlock();
            return -EFAULT;
        }

        if (info.pwd && copy_to_user(info.pwd, "(none)", 6))
        {
            spin_unlock(&pid_info_lock);
            rcu_read_unlock();
            return -EFAULT;
        }

        if (copy_to_user(user_ret, &info, sizeof(info)))
        {
            spin_unlock(&pid_info_lock);
            rcu_read_unlock();
            return -EFAULT;
        }

        spin_unlock(&pid_info_lock);
        rcu_read_unlock();
        return 0;
    }

    info.time = ns_to_timespec64(ktime_get_ns() - task->start_time);
    info.nb_childs = 0;
    list_for_each_entry(child, &task->children, sibling)
    {
        info.nb_childs++;
    }

    if (info.nb_childs > info.childs_len / sizeof(pid_t))
    {
        spin_unlock(&pid_info_lock);
        rcu_read_unlock();
        return -ENOMEM;
    }

    tmp = info.child_pids;
    list_for_each_entry(child, &task->children, sibling)
    {
        if (copy_to_user(tmp, &child->pid, sizeof(pid_t)))
        {
            spin_unlock(&pid_info_lock);
            rcu_read_unlock();
            return -EFAULT;
        }
        tmp++;
    }

    spin_unlock(&pid_info_lock);
    rcu_read_unlock();

    if (user_ret->exe)
        if (get_exe(user_ret->exe, PATH_MAX, task))
            return -EFAULT;

    if (user_ret->root_path)
        if (get_root(user_ret->root_path, PATH_MAX, task))
            return -EFAULT;

    if (user_ret->pwd)
        if (get_pwd(user_ret->pwd, PATH_MAX, task))
            return -EFAULT;

    if (copy_to_user(user_ret, &info, sizeof(info)))
        return -EFAULT;

    return 0;
}
