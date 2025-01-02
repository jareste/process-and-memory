#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

#define __NR_ft_fork 549

int main()
{
    pid_t pid;

    pid = syscall(__NR_ft_fork);

    if (pid == -1)
    {
        perror("syscall");
        return 1;
    }

    if (pid == 0)
    {
        printf("Child process created successfully with PID: %d\n", getpid());
        exit(34);
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
            printf("Child exited with status: %d\n", WEXITSTATUS(status));
        }
        else
        {
            printf("Child did not exit normally\n");
            return 1;
        }
    }

    return 0;
}
