#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int syscall_no = *(int*)(f->esp); 
 
  switch (syscall_no) 
  { 
    case SYS_HALT : 
    { 
      shutdown_power_off(); 
      break; 
    } 
    case SYS_EXIT : 
    { 
      int status = *(int*)(f->esp + 4); 

      exit(status); 
      break; 
    } 
    case SYS_WRITE : 
    { 
      int fd = *(int*)(f->esp + 4); 
      const char* buffer = *(char **)(f->esp + 8); 
      unsigned size = *(unsigned *)(f->esp + 12); 
       
      write(fd, buffer, size);
      break; 
    } 
  } 
} 
 
void exit(int status) 
{ 
  struct thread *t = thread_current(); 
  printf ("%s: exit(%d)\n", t->name, status); 
 
  thread_exit(); 
} 
void write(int fd, char* buffer, unsigned size)
{
  if (fd == 1) 
      { 
        putbuf(buffer, size); 
      } 
}