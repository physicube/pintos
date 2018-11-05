#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
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
      struct thread *t = thread_current();

      printf ("%s: exit(%d)\n", t->name, status); 
      t->exit_status = status;
      thread_exit();

      lock_acquire(&t->syscall_lock);
      cond_signal(&t->syscall_condvar, &t->syscall_lock);
      lock_release(&t->syscall_lock);


      f->eax = status;
      break; 
    }
    case SYS_EXEC :
    {
      char *cmd_line = *(char **)(f->esp + 4);
      struct thread *parent = thread_current();
      
      pid_t pid = process_execute(cmd_line);
      
      if (pid != PID_ERROR)
      {
        struct thread *child = tid_to_thread(pid);
        struct child_thread *ct  = malloc(sizeof(struct child_thread));
        struct condition *condvar = &child->syscall_condvar;
        struct lock *lock = &child->syscall_lock;

        lock_acquire(lock);

        while(!child->load_success)
          cond_wait(condvar, lock);

        lock_release(lock);

        ct->child = child;
        list_push_back(&parent->child_threads, &ct->elem);
        child->parent = parent;
      }

      f->eax = pid;
      break;
    }
    case SYS_WAIT :
    {
      pid_t pid = *(pid_t *)(f->esp + 4); 
      
      f->eax = process_wait(pid);
      break;
    }
    case SYS_CREATE :
    {
      const char *file = *(char **)(f->esp + 4); 
      unsigned initial_state = *(unsigned *)(f->esp + 8); 

      f->eax = filesys_create(file, initial_state);
      break;
    }
    case SYS_REMOVE :
    {
      const char *file = *(char **)(f->esp + 4); 
      // maybe some kind of issue can occur
      f->eax = filesys_remove(file);
      break;
    }
    case SYS_OPEN :
    {
      const char *file = *(char **)(f->esp + 4); 

      break;
    }
    case SYS_FILESIZE :
    {
      int fd = *(int *)(f->esp + 4);

      break;
    }
    case SYS_READ :
    {
      break;
    }
    case SYS_WRITE : 
    { 
      int fd = *(int *)(f->esp + 4); 
      const char* buffer = *(char **)(f->esp + 8); 
      unsigned size = *(unsigned *)(f->esp + 12); 
       
      if (fd == 1) 
        putbuf(buffer, size);

      f->eax = size;
      break; 
    }
    case SYS_SEEK :
    {
      break;
    }
    case SYS_TELL :
    {
      break;
    }
    case SYS_CLOSE :
    {
      break;
    }
  } 
} 