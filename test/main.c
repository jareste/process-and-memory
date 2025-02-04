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

static int check_condition(const char *description, int condition)
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

static void test_zombie_process()
{
    pid_t pid = fork();

    if (pid == 0)
    {
        exit(127);
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
            check_condition("PID is correct", info.pid == pid);
            check_condition("Parent PID is correct", info.parent_pid == getpid());
            check_condition("Age is greater than 0", info.age > 0);
            check_condition("Number of childs is 0", info.nb_childs == 0);
            check_condition("Stack pointer is NULL", info.stack_ptr == NULL);
        }

        waitpid(pid, NULL, 0);
    }
    else
    {
        perror("fork");
    }
} /* Zombie test end */

static void syscall_unit_test(int pid, const char *description, int expect_errno)
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

static void *thread_test(void *arg)
{
    int pid = *(int *)arg;
    syscall_unit_test(pid, "Threaded syscall test", 0);
    return NULL;
}

static void extended_tests()
{
    printf("\nRunning extended tests for get_pid_info syscall...\n\n");

    /* Again Edge Cases */
    syscall_unit_test(0, "Zero PID", ESRCH);
    syscall_unit_test(-1, "Negative PID", ESRCH);
    syscall_unit_test(INT_MAX, "Maximum PID", ESRCH);

    /* TODO check permission handling */
    printf("[INFO] Skipping permission tests (requires manual setup or root privileges)\n");

    /* it must fail due to short child_pids buffer*/
    struct pid_info info;
    pid_t child_pids[2];
    info.child_pids = child_pids;
    info.childs_len = sizeof(child_pids);
    long result = syscall(SYS_get_pid_info, &info, getpid());
    if (check_condition("Small buffer for child processes", result == -1) == 0)
    {
        printf("Expected return value: -ENOMEM, Actual return value: %ld\n", result);
    }

    /* Stress test */    
    printf("\nRunning stress test with many threads...\n");
    pthread_t threads[50];
    int test_pid = getpid();
    for (int i = 0; i < 50; i++)
    {
        pthread_create(&threads[i], NULL, thread_test, &test_pid);
    }
    for (int i = 0; i < 50; i++)
    {
        pthread_join(threads[i], NULL);
    }

    /* TESTING 1 again*/
    syscall_unit_test(1, "System Process (PID 1)", 0); /* init */
    syscall_unit_test(2, "System Process (PID 2)", 0); /* kthread */
    syscall_unit_test(3, "System Process (PID 3)", 0); /* ksoftirqd */

    printf("\nExtended tests complete.\n");
}

static void run_tests()
{
    printf("Running unit tests for get_pid_info syscall...\n\n");

    syscall_unit_test(getpid(), "Current process PID", 0);

    syscall_unit_test(1, "Init process PID", 0);

    syscall_unit_test(99999, "Non-existent PID", ESRCH);

    syscall_unit_test(-1, "-1 PID", ESRCH);
    syscall_unit_test(0, "0 PID", ESRCH);

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

    test_zombie_process();
    test_zombie_process();

    extended_tests();
    extended_tests();

    printf("\nSummary of test results:\n");
    printf("Passed: %d\n", passed);
    printf("Failed: %d\n", failed);
}

int main()
{
    run_tests(); 
    return failed > 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
