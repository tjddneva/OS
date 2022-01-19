#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "lib/user/syscall.h"
void syscall_init (void);
void check_pointer(void* address);
void exit(int status);
pid_t exec(const char* cmd_line);
int fibonacci(int n);
int max_of_four_int(int a, int b, int c, int d);
#endif /* userprog/syscall.h */
