#include <mach/mach.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
    mach_port_t task = MACH_PORT_NULL;
    kern_return_t result = task_for_pid(mach_task_self(), getppid(), &task);
    printf("task_for_parent=%d port=%u\n", result, task);
    if (task != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), task);
    return result == KERN_SUCCESS ? 0 : 1;
}
