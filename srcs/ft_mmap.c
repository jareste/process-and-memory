#include <linux/mm.h>
#include <linux/syscalls.h>

SYSCALL_DEFINE6(ft_mmap, unsigned long, addr, size_t, length, int, prot, int, flags, int, fd, off_t, offset)
{
    struct file *file = NULL;

    if (!length)
        return -EINVAL;

    if (fd >= 0)
    {
        file = fget(fd);
        if (!file)
            return -EBADF;
    }

    unsigned long ret = vm_mmap(file, addr, length, prot, flags, offset);

    if (file)
        fput(file);

    return ret;
}
