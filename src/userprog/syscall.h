#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/interrupt.h"
#include "filesys/file.h"
#include <list.h>
#define STDIN 0
#define STDOUT 1
#define STDERR 2

struct mmap_str
{
    int id;
    struct file * file;
    void * uaddr;
    size_t file_size;
    struct list_elem elem;
};

void syscall_init (void);
bool check_validate(void *addr);
void sys_exit(int , struct intr_frame * UNUSED);
#endif /* userprog/syscall.h */