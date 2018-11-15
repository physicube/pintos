#include "userprog/syscall.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

static void syscall_handler (struct intr_frame *);
static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
static void get_arg(void *arg, uint8_t *esp, int size);
static bool valid_pointer(void *esp);
static bool valid_addr(void *esp);

void sys_exit(int, struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  int syscall_no;
  get_arg(&syscall_no, f->esp, sizeof(int)); 
 
  switch (syscall_no) 
  { 
    case SYS_HALT : 
    { 
      shutdown_power_off(); 
      break; 
    } 
    case SYS_EXIT : 
    { 
      int status;
      get_arg(&status, f->esp + 4, 4);

      sys_exit(status, f);
      break; 
    }
    case SYS_EXEC :
    {
      char *arg;
      get_arg(&arg, f->esp + 4, 4);
      char *cmd_line = malloc(strlen(arg) + 1);
      strlcpy(cmd_line, arg, strlen(arg) + 1);
      pid_t pid = process_execute(cmd_line);

      f->eax = pid;
      break;
    }
    case SYS_WAIT :
    {
      pid_t pid;
      get_arg(&pid, f->esp + 4, 4); 
      
      f->eax = process_wait(pid);
      break;
    }
    case SYS_CREATE :
    {
      char *file;
      unsigned initial_state;
      get_arg(&file, f->esp + 4, 4); 
      get_arg(&initial_state, f->esp + 8, 4); 

      f->eax = filesys_create(file, initial_state);
      break;
    }
    case SYS_REMOVE :
    {
      char *file;
      get_arg(&file, f->esp + 4, 4); 
      // maybe some kind of issue can occur
      f->eax = filesys_remove(file);
      break;
    }
    case SYS_OPEN :
    {
      char *file;
      get_arg(&file, f->esp + 4, 4); 

      break;
    }
    case SYS_FILESIZE :
    {

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

void sys_exit(int status, struct intr_frame *f)
{
  struct thread *t = thread_current();
  printf("%s: exit(%d)\n", t->name, status);
  t->exit_status = status;
  thread_exit();

  f->eax = status;
}

static bool valid_pointer(void *esp)
{
  if (get_user(esp) != -1 && valid_addr(esp))
    return true;
  else
    return false;
}

static bool valid_addr(void *esp)
{
  struct thread *t = thread_current();
  
  if (pagedir_get_page(t->pagedir, esp) != NULL && esp < PHYS_BASE)
    return true;
  else 
    return false;
}


static void get_arg(void *arg, uint8_t *esp, int size)
{
  for (int i = 0; i < size; i++)
  {
    if (valid_pointer(esp + i))
      *(char *)(arg + i) = (uint8_t)get_user(esp + i);
    else 
      sys_exit(-1, NULL);
  }
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}
 
/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}