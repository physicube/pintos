#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/interrupt.h"
#define STDIN 0
#define STDOUT 1
#define STDERR 2

void syscall_init (void);
void sys_exit(int , struct intr_frame * UNUSED);
#endif /* userprog/syscall.h */
