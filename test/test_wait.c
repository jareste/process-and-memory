#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

#define __NR_ft_wait 552
#define GREEN "\033[0;32m"
#define RED "\033[0;31m"
#define RESET "\033[0m"

int main()
{
    pid_t pid;
    int status;
    int ret;

    printf("\n#### Test ft_wait syscall ####\n");

    pid = fork();

    if (pid == 0)
    {
        exit(0);
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
            printf(GREEN);
            printf("ft_wait returned the correct PID: %d\n", ret);
            printf(RESET);
        }
        else
        {
            printf(RED);
            printf("ft_wait returned an incorrect PID: %d\n", ret);
            printf(RESET);
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
