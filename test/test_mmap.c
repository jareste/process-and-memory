#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>

#define __NR_ft_mmap 551

int main()
{
    int fd;
    void *addr;
    size_t length = 4096;
    int prot = PROT_READ | PROT_WRITE;
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    off_t offset = 0;

    fd = open("/dev/zero", O_RDWR);
    if (fd == -1)
    {
        perror("open");
        return 1;
    }

    addr = (void *)syscall(__NR_ft_mmap, 0, length, prot, flags, fd, offset);

    if (addr == MAP_FAILED)
    {
        perror("syscall");
        close(fd);
        return 1;
    }

    printf("ft_mmap syscall succeeded, mapped address: %p\n", addr);

    sprintf((char *)addr, "Hello, mmap!");

    printf("Read from mmap: %s\n", (char *)addr);

    if (munmap(addr, length) == -1)
    {
        perror("munmap");
        close(fd);
        return 1;
    }

    close(fd);
    return 0;
}