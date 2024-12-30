#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>

struct pid_info {
    int pid;
    int state;
    void *stack_ptr;
    unsigned long age;
    int child_pids[64];
    int parent_pid;
    char root_path[256];
    char pwd[256];
};

#define SYS_get_pid_info 548

int main(int argc, char *argv[])
{
    int pid;
    if (argc == 2)
    {
        pid = atoi(argv[1]);
    }
    else
    {
        pid = getpid();
    }

    struct pid_info info;

    long result = syscall(SYS_get_pid_info, &info, pid);
    if (result != 0)
    {
        fprintf(stderr, "Error calling syscall: %s\n", strerror(errno));
        return 1;
    }

    printf("PID: %d\n", info.pid);
    printf("State: %d\n", info.state);
    printf("Stack Pointer: %p\n", info.stack_ptr);
    printf("Age (ms): %lu\n", info.age);
    printf("Parent PID: %d\n", info.parent_pid);
    printf("Root Path: %s\n", info.root_path);
    printf("Current Working Directory: %s\n", info.pwd);

    printf("Child PIDs: ");
    for (int i = 0; i < 64 && info.child_pids[i] != 0; i++)
    {
        printf("%d ", info.child_pids[i]);
    }
    printf("\n");

    return 0;
}