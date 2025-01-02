#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <sys/wait.h>

struct pid_info {
    int             pid;
    int             state;
    void*           stack_ptr;
    unsigned long   age;
    struct timespec time;
    size_t          nb_childs;
    pid_t*          child_pids;
    size_t          childs_len;
    pid_t           parent_pid;
    char*           exe;
    char*           root_path;
    char*           pwd;
};

#define SYS_get_pid_info 548
#define GREEN "\033[0;32m"
#define RED "\033[0;31m"
#define RESET "\033[0m"

void check_condition(const char* description, int condition)
{
    if (condition)
    {
        printf(GREEN "[PASS] %s" RESET "\n", description);
    }
    else
    {
        printf(RED "[FAIL] %s" RESET "\n", description);
    }
}

void test_zombie_process()
{
    pid_t pid = fork();

    if (pid == 0)
    {
        exit(0);
    }
    else if (pid > 0)
    {
        sleep(1);

        struct pid_info info;
        pid_t child_pids[128];
        char exe[PATH_MAX], root_path[PATH_MAX], pwd[PATH_MAX];

        info.child_pids = child_pids;
        info.childs_len = sizeof(child_pids);
        info.exe = exe;
        info.root_path = root_path;
        info.pwd = pwd;

        long result = syscall(SYS_get_pid_info, &info, pid);

        if (result != 0)
        {
            printf(RED "[FAIL] Syscall failed for zombie process" RESET "\n");
            printf("Error: %s (errno: %d)\n", strerror(errno), errno);
        }
        else
        {
            check_condition("Zombie process detected", info.state == 'Z');
            check_condition("Executable path is [zombie]", strcmp(info.exe, "[zombie]") == 0);
            check_condition("Root path is unavailable", strcmp(info.root_path, "(unavailable)") == 0);
            check_condition("PWD is unavailable", strcmp(info.pwd, "(unavailable)") == 0);
        }

        waitpid(pid, NULL, 0);
    }
    else
    {
        perror("fork");
    }
}

int main()
{
    printf("Testing get_pid_info with zombie process...\n");
    test_zombie_process();
    return 0;
}
