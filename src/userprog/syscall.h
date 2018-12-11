#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/interrupt.h"
#include "threads/thread.h"
#define STDIN 0
#define STDOUT 1
#define STDERR 2


struct mmap_str 
{
  int id;
  void *addr;   
  size_t file_size;  
  struct file* file;

  struct list_elem elem;
};

int mmfiles_insert (void *addr, struct file* file, int32_t len);
static struct mmap_str* find_mmap_str(struct thread *t, int mid);
void syscall_init (void);
bool check_validate(void *addr);
void sys_exit(int , struct intr_frame * UNUSED);
#endif 