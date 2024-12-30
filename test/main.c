#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <limits.h>

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

/* Task states
 * R: Running
 * S: Sleeping in an interruptible wait
 * D: Waiting in uninterruptible disk sleep
 * Z: Zombie
 * T: Stopped (on a signal) or (trace stopped)
 * t: Tracing stop
 * X: Dead EXIT
 * x: Dead task dead
 * K: Wakekill (killed while waking)
 * W: Waking
 * P: Parked
 * I: Idle
 */

int main(int argc, char *argv[])
{
    int pid;
    if (argc == 2)
        pid = atoi(argv[1]);
    else
        pid = getpid();
    
    struct pid_info info;
    pid_t child_pids[64];
    char exe[PATH_MAX], root_path[PATH_MAX], pwd[PATH_MAX];

    info.child_pids = child_pids;
    info.childs_len = sizeof(child_pids);
    info.exe = exe;
    info.root_path = root_path;
    info.pwd = pwd;

    long result = syscall(SYS_get_pid_info, &info, pid);
    if (result != 0)
    {
        fprintf(stderr, "Error calling syscall: %s\n", strerror(errno));
        return 1;
    }

    printf("PID: %d\n", info.pid);
    printf("State: %c\n", info.state);
    printf("Stack Pointer: %p\n", info.stack_ptr);
    printf("Age (ms): %lu\n", info.age);
    printf("Parent PID: %d\n", info.parent_pid);
    printf("Executable: %s\n", info.exe);
    printf("Root Path: %s\n", info.root_path);
    printf("Current Working Directory: %s\n", info.pwd);

        printf("Child PIDs: ");

    if (info.nb_childs == 0)
        printf("No child processes");
    else
        for (size_t i = 0; i < info.nb_childs; i++)
            printf("%d ", info.child_pids[i]);

    printf("\n");

    return 0;
}
