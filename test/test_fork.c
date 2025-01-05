#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

#define __NR_ft_fork 549
#define GREEN "\033[0;32m"
#define RED "\033[0;31m"
#define RESET "\033[0m"

#define EXIT_STATUS 34

int main()
{
    pid_t pid;

    printf("\n#### Test ft_fork syscall ####\n");

    pid = syscall(__NR_ft_fork);

    if (pid == -1)
    {
        perror("syscall");
        return 1;
    }

    if (pid == 0)
    {
        printf(GREEN);
        printf("Child process created successfully with PID: %d\n", getpid());
        printf(RESET);
        exit(EXIT_STATUS);
    }
    else
    {
        printf("Parent process, child PID: %d\n", pid);

        int status;
        if (waitpid(pid, &status, 0) == -1)
        {
            perror("waitpid");
            return 1;
        }

        if (WIFEXITED(status))
        {
            if (WEXITSTATUS(status) == EXIT_STATUS)
            {
                printf(GREEN);
                printf("Child exited with expected status: %d\n", WEXITSTATUS(status));
                printf(RESET);
            }
            else
            {
                printf(RED);
                printf("Child exited with unexpected status: %d\n", WEXITSTATUS(status));
                printf(RESET);
                return 1;
            }
        }
        else
        {
            printf(RED);
            printf("Child did not exit normally\n");
            printf(RESET);
            return 1;
        }
    }

    return 0;
}
