#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <assert.h>
#include <pthread.h>
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

int passed = 0;
int failed = 0;

int check_condition(const char *description, int condition)
{
    if (condition)
    {
        printf(GREEN "[PASS] %s" RESET "\n", description);
        passed++;
        return 1;
    }
    else
    {
        printf(RED "[FAIL] %s" RESET "\n", description);
        failed++;
        return 0;
    }
}

void syscall_unit_test(int pid, const char *description, int expect_errno)
{
    struct pid_info info;
    pid_t child_pids[128];
    char exe[PATH_MAX], root_path[PATH_MAX], pwd[PATH_MAX];

    info.child_pids = child_pids;
    info.childs_len = sizeof(child_pids);
    info.exe = exe;
    info.root_path = root_path;
    info.pwd = pwd;

    long result = syscall(SYS_get_pid_info, &info, pid);

    if (expect_errno == 0)
    {
        if (check_condition(description, result == 0) == 0)
        {
            printf("Expected return value: 0, Actual return value: %ld, pid: %d\n", result, pid);
            return;
        }
        if (result == 0)
        {
            if (check_condition("PID matches requested PID", info.pid == pid) == 0)
            {
                printf("Expected PID: %d, Actual PID: %d\n", pid, info.pid);
            }

            if (check_condition("State is valid", info.state > 0) == 0)
            {
                printf("Invalid state: %d\n", info.state);
            }

            if (check_condition("Executable path is not empty", strlen(info.exe) > 0) == 0)
            {
                printf("Empty exe path\n");
            }

            if (check_condition("Root path is not empty", strlen(info.root_path) > 0) == 0)
            {
                printf("Empty root path\n");
            }
            
            if (check_condition("PWD is not empty", strlen(info.pwd) > 0) == 0)
            {
                printf("Empty pwd\n");
            }
        }
    }
    else
    {
        if (check_condition(description, result == -1 && errno == expect_errno) == 0)
            printf("Expected errno: %d, Actual errno: %d\n", expect_errno, errno);
    }
}

void *thread_test(void *arg)
{
    int pid = *(int *)arg;
    syscall_unit_test(pid, "Threaded syscall test", 0);
    return NULL;
}

void run_tests()
{
    printf("Running unit tests for get_pid_info syscall...\n\n");

    syscall_unit_test(getpid(), "Current process PID", 0);

    syscall_unit_test(1, "Init process PID", 0);

    syscall_unit_test(99999, "Non-existent PID", ESRCH);

    struct pid_info invalid_info = {0};
    long result = syscall(SYS_get_pid_info, &invalid_info, getpid());

    if (check_condition("Invalid buffers test", result == -1 && errno == EFAULT) == 0)
    {
        printf("Expected errno: %d, Actual errno: %d\n", EFAULT, errno);
        printf("Expected return value: -1, Actual return value: %ld\n", result);
    }

    if (fork() == 0)
        exit(0);
    else
    {
        sleep(1);
        syscall_unit_test(getpid(), "Zombie process test", 0);
    }

    printf("\nRunning concurrency test with multiple threads...\n");
    int test_pids[] = {getpid(), 1};
    pthread_t threads[2];

    for (int i = 0; i < 2; i++)
        pthread_create(&threads[i], NULL, thread_test, &test_pids[i]);

    for (int i = 0; i < 2; i++)
        pthread_join(threads[i], NULL);

    printf("\nSummary of test results:\n");
    printf("Passed: %d\n", passed);
    printf("Failed: %d\n", failed);
}

int main()
{
    // run_tests();
    pid_t pid = fork();

    if (pid == 0)
    {
        exit(0);
    }
    else if (pid > 0)
    {
        sleep(1);
        

        syscall_unit_test(pid, "Zombie process test", 0);
        printf("Expected errno: %d, Actual errno: %d\n", EFAULT, errno);

        waitpid(pid, NULL, 0);
    }
    else
    {
        perror("fork");
        return 1;
    }

 
    return failed > 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
