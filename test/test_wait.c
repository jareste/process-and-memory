#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

#define __NR_ft_wait 552

int main()
{
    pid_t pid;
    int status;
    int ret;

    pid = fork();

    if (pid == 0)
    {
        exit(42);
    }
    else if (pid > 0)
    {
        sleep(1);

        ret = syscall(__NR_ft_wait, &status);

        if (ret == -1)
        {
            perror("syscall");
            return 1;
        }

        if (ret == pid)
        {
            printf("ft_wait returned the correct PID: %d\n", ret);
        }
        else
        {
            printf("ft_wait returned an incorrect PID: %d\n", ret);
            return 1;
        }

        if (status == 42)
        {
            printf("ft_wait returned the correct status: %d\n", status);
        }
        else
        {
            printf("ft_wait returned an incorrect status: %d\n", status);
            return 1;
        }

        waitpid(pid, NULL, 0);
    }
    else
    {
        perror("fork");
        return 1;
    }

    return 0;
}
