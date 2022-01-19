#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "userprog/process.h"
#include "lib/user/syscall.h"

void syscall_init (void);
void check_pointer(void*);

void exit(int status);
pid_t exec(const char *);

int sys_open(const char *file);
int sys_read(int fd,void *buffer, unsigned size);
int sys_write(int fd, const void *buffer,unsigned size);
void sys_close(int fd);

#ifdef VM
bool sys_munmap(mmapid_t);
#endif


#endif /* userprog/syscall.h */
