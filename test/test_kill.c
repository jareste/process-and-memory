#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>

#define __NR_ft_kill 550

int signum;

void signal_handler(int sig)
{
    printf("Received signal: %d, expected: %d\n", sig, signum);
}

int main(int argc, char *argv[])
{
    pid_t pid;
    int ret;
    
    if (argc > 1)
    {
        signum = atoi(argv[1]);
    }
    else
    {
        signum = SIGUSR1;
    }

    pid = fork();

    if (pid == 0)
    {
        signal(signum, signal_handler);
        printf("Child process waiting for signal...\n");
        pause();
        exit(0);
    }
    else if (pid > 0)
    {
        sleep(1);

        ret = syscall(__NR_ft_kill, pid, signum);

        if (ret == -1)
        {
            perror("syscall");
            return 1;
        }

        printf("ft_kill syscall returned successfully\n");

        waitpid(pid, NULL, 0);
    }
    else
    {
        perror("fork");
        return 1;
    }

    return 0;
}