#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h" // for SYS_HALT
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/block.h"
#include "filesys/free-map.h"
#include "filesys/directory.h"
#include "filesys/inode.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "lib/kernel/list.h"
#include "devices/input.h"
#include "vm/frame.h"
#include "vm/page.h"

static void syscall_handler (struct intr_frame *);
int read_phys_mem(unsigned char *addr);
struct lock memory_lock;
bool check_validate(void *addr);
void check_memory_byte_by_byte(void * addr, size_t size);
void read_mem(void *f, unsigned char *esp, int num);
bool write_mem(unsigned char *addr, unsigned char byte);
void sys_exit(int , struct intr_frame * UNUSED);
void sys_wait(int , struct intr_frame *);
void sys_write(int , void*, int, struct intr_frame *);
void sys_exec(char *, struct intr_frame *);
void sys_create(char *, size_t, struct intr_frame *);
void sys_open(char *, struct intr_frame *);
void sys_close(int , struct intr_frame * UNUSED);
void sys_read(int, void*,int, struct intr_frame *);
void sys_filesize(int , struct intr_frame*);
void sys_remove(char *, struct intr_frame*);
void sys_seek(int, int, struct intr_frame * UNUSED);
void sys_tell(int , struct intr_frame *f);
void sys_mmap(int, void*, struct intr_frame *);
void sys_munmap(int);
static struct filedescriptor * find_fd(int fd_);

void
syscall_init (void) 
{
  lock_init(&memory_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void check_memory_byte_by_byte(void * addr, size_t size)
{
  unsigned char *_cmd = addr;
  for(unsigned i = 0; i < size; i++)
    if(!check_validate((void *)(_cmd + i)))
      sys_exit(-1, NULL);
}

int read_phys_mem(unsigned char *addr)
{
  /*Reads a byte at user virtual address UADDR.
          UADDR must be below PHYS_BASE.
          Returns the byte value if successful, -1 if a segfault
          occurred. */
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:": "=&a" (result) : "m" (*addr));
  return result;
}

bool write_mem(unsigned char *addr, unsigned char byte)
{
  if(check_validate(addr))
  {
    int error_code;
    /* Writes BYTE to user address UDST.
    UDST must be below PHYS_BASE.
    Returns true if successful, false if a segfault occurred. */
    asm ("movl $1f, %0; movb %b2, %1; 1:"
        : "=&a" (error_code), "=m" (*addr) : "q" (byte));
    return error_code != -1;
  }
  else
    sys_exit(-1,NULL);
    return false;
  //p
}

bool check_validate(void *addr)
{
  if((addr != NULL) && (((unsigned int)addr) < ((unsigned int)PHYS_BASE)))
  {
    if(pagedir_get_page(thread_current()->pagedir, addr) != NULL)
      return true;
    else
      return false;
  }
  return false;
}

void read_mem(void *f, unsigned char *esp, int num)
{
  for(int i = 0; i < num; i++)
  {
    if(check_validate(esp + i))
      *(char *)(f + i) = read_phys_mem(esp + i) & 0xff;
    else
      sys_exit(-1,NULL);
  }
}

static void
syscall_handler (struct intr_frame *f) 
{
  int syscall_number;

  void *esp = f->esp;
  thread_current()->esp = f->esp;
  if(!check_validate(esp) && !check_validate(esp+4) && ! check_validate(esp+8) && !check_validate(esp+12))
    sys_exit(-1,NULL);
  read_mem(&syscall_number, esp, sizeof(syscall_number));
  printf("[SYSCALL!] sysnumber : %d\n",syscall_number);
  switch(syscall_number)
  {
    case SYS_HALT: 
    {
      shutdown_power_off();
      break;
    }
    case SYS_EXIT: 
    { 
      int exit_code;
      read_mem(&exit_code, esp+4, sizeof(exit_code));
      sys_exit(exit_code,f);
      break;
    }
    case SYS_EXEC: 
    { 
      void * cmd;
      read_mem(&cmd, esp+4, sizeof(cmd));
      sys_exec(cmd,f);
      break;
    }
    case SYS_WAIT:
    { 
      int tid;
      read_mem(&tid,esp+4,sizeof(tid));
      sys_wait(tid,f);
      break;
    }
    case SYS_CREATE: 
    {
      char * name;
      size_t size;
      read_mem(&name, esp+4, sizeof(name));
      read_mem(&size, esp+8, sizeof(size));
      sys_create(name,size,f);
      break;
    }
    case SYS_REMOVE: 
    {
      char * name;
      read_mem(&name,esp+4,sizeof(name));
      sys_remove(name,f);
      break;
    }
    case SYS_OPEN: 
    {
      char *name;

      read_mem(&name, esp+4, sizeof(name));
      sys_open(name,f);
      break;
    }
    case SYS_FILESIZE: 
    {
      int fd;
      read_mem(&fd,esp+4,sizeof(fd));
      sys_filesize(fd,f);
      break;
    }
    case SYS_READ:
    {
      int fd, size;
      void *buffer;
      read_mem(&fd,esp+4,sizeof(fd));
      read_mem(&buffer, esp+8, sizeof(fd));
      read_mem(&size, esp+12, sizeof(fd));
      sys_read(fd,buffer,size,f);
      
      break;
    }
    case SYS_WRITE: 
    { 
      int fd, size;
      void *buffer;
      read_mem(&fd,esp+4,sizeof(fd));
      read_mem(&buffer, esp+8, sizeof(buffer));
      read_mem(&size, esp+12, sizeof(size));
      sys_write(fd,buffer,size,f);
      break;
    }
    case SYS_SEEK: 
    {
      int fd, cnt;
      read_mem(&fd,esp+4,sizeof(fd));
      read_mem(&cnt,esp+8,sizeof(cnt));
      sys_seek(fd, cnt, f);
      break;
    }
    case SYS_TELL: 
    {
      int fd;
      read_mem(&fd,esp+4,sizeof(fd));
      sys_tell(fd,f);
      break;
    }
    case SYS_CLOSE: 
    {
      int fd;
      read_mem(&fd, esp+4, sizeof(fd));
      sys_close(fd,f);
      break;
    }
    case SYS_MMAP:
    {
      int fd;
      void *addr;
      read_mem(&fd, esp+4, sizeof(fd));
      read_mem(&addr, esp+8, sizeof(addr));
      sys_mmap(fd,addr,f);
      break;
    }
    case SYS_MUNMAP:
    {
      int mid;
      read_mem(&mid, esp+4, sizeof(mid));
      sys_munmap(mid);
      break;
    }
    default:
    {
      int exit_code;
      read_mem(&exit_code, esp+4,sizeof(exit_code));
      sys_exit(exit_code,NULL);
    }
  }
}

void
sys_exit(int exit_code, struct intr_frame *f UNUSED)
{
  struct thread *t = thread_current();
  struct tcb * tcb = t->tcb;
  printf("%s: exit(%d)\n", t->name, exit_code);
  if(tcb) tcb->exit_code = exit_code;
  thread_exit();
}

void 
sys_wait(int tid, struct intr_frame *f)
{
  f->eax = process_wait(tid);
}

void
sys_exec(char *cmd, struct intr_frame *f)
{
  check_memory_byte_by_byte(cmd,sizeof(cmd));
  lock_acquire(&memory_lock);
  f->eax = process_execute((const char*)cmd);
  lock_release(&memory_lock);
}

void
sys_create(char *name, size_t size, struct intr_frame *f)
{
  check_memory_byte_by_byte(name,sizeof(name));
  lock_acquire(&memory_lock);
  f->eax = filesys_create((const char*)name, size);
  lock_release(&memory_lock);
}

void 
sys_write(int fd_, void * buffer, int size, struct intr_frame *f)
{
  if(buffer == NULL)
    sys_exit(-1,NULL);
  check_memory_byte_by_byte(buffer, sizeof(buffer));
  if(!check_validate(buffer) || !check_validate(buffer+size))
    sys_exit(-1,NULL);
  
  lock_acquire(&memory_lock);
  if(fd_ == STDOUT)
  {
    putbuf(buffer, size);
    lock_release(&memory_lock);
    f->eax = size;
  }
  else if(fd_ == STDIN)
  {
    f->eax = -1;
    lock_release(&memory_lock);
    return;
  }
  else if( !fd_validate(fd_) || fd_ < 0)
  {  
    f->eax = -1;
    lock_release(&memory_lock);
    return;
  }
  else
  {
    struct filedescriptor * fd = find_fd(fd_);

    if(fd != NULL)
    {
      if (fd->f != NULL)
      {
        struct SPTE * spte;
        void *vaddr;
        struct SPTABLE *supt = thread_current()->supt;
        uint32_t *pagedir = thread_current()->pagedir;
        for(vaddr = pg_round_down(buffer); vaddr < buffer + size; vaddr += PGSIZE)
        {
          spte = find_page_by_vaddr(supt, vaddr);
          load_page(supt, pagedir, vaddr);
          frame_set_is_evict(spte->paddr, true);
        }
        f->eax = file_write(fd->f, buffer, size);
        for(vaddr = pg_round_down(buffer); vaddr < buffer + size; vaddr += PGSIZE)
        {
          spte = find_page_by_vaddr(supt, vaddr);
          frame_set_is_evict(spte->paddr, false);
        }
          lock_release(&memory_lock);
          return;
      }
    }
    else
    {
      lock_release(&memory_lock);
      f->eax=-1;
      return;
    }
  }
}

void
sys_open(char * name, struct intr_frame *f)
{
  struct file * open = NULL;
  struct filedescriptor * fd;
  struct thread *t = thread_current();
  
  check_memory_byte_by_byte(name,sizeof(name));
  lock_acquire(&memory_lock);
  
  fd = palloc_get_page(0);
  if(fd == NULL)
  {
    palloc_free_page(fd);
    goto malicious_ending;
  }
  else
  {
    open = filesys_open(name);
    if(open == NULL)
      goto malicious_ending;
    fd->f = open;  
    fd->fd_num = thread_get_fd_max();
    fd->master = t;
    list_push_back(&t->fd, &fd->elem);

    f->eax = fd->fd_num;
    lock_release(&memory_lock);
    //printf("[SYS_OPEN] : fd : %d, name : %s\n",fd->fd_num, name);
    return;
  }
  malicious_ending:
  f->eax = -1;
  lock_release(&memory_lock);
}

void
sys_close(int fd_, struct intr_frame *f UNUSED)
{  
  struct thread *t = thread_current();

  if(!list_empty(&t->fd))
  {
    lock_acquire(&memory_lock);
    struct filedescriptor *fd = find_fd(fd_);;
    if (fd == NULL)
      return;
    if(t->tid == fd->master->tid) // check master thread.
    {
      file_close(fd->f);
      list_remove(&(fd->elem));
      palloc_free_page(fd);
    }
    lock_release(&memory_lock);
  }
}

void
sys_read(int fd_, void * buffer, int size, struct intr_frame *f)
{
    printf("[Sys read] sysnum : %d, buffer : %p \n",fd_, buffer);

  check_memory_byte_by_byte(buffer, sizeof(buffer)+size-1);
  lock_acquire(&memory_lock);
  if(fd_ == STDIN) 
  {
    for(unsigned i = 0; i < (unsigned)size; i++)
      write_mem((unsigned char *)(buffer + i), input_getc());
    lock_release(&memory_lock);
    f->eax = size;
  }
  else if(fd_ == STDOUT)
  {
    f->eax = -1;
    lock_release(&memory_lock);
    return;
  }
  else if(!fd_validate(fd_) || fd_ < 0)
  {
    f->eax = -1;
    lock_release(&memory_lock);
    return;
  }
  else
  {
    struct filedescriptor *fd = find_fd(fd_);
    if(fd != NULL)
    {
      struct SPTE * spte;
      void *vaddr;
      struct SPTABLE *supt = thread_current()->supt;
      uint32_t *pagedir = thread_current()->pagedir;

      for(vaddr = pg_round_down(buffer); vaddr < buffer + size; vaddr += PGSIZE)
      {
        spte = find_page_by_vaddr(supt, vaddr);
        load_page(supt, pagedir, vaddr);
        frame_set_is_evict(spte->paddr, true);
      }
      f->eax = file_read(fd->f, buffer,size);
      for(vaddr = pg_round_down(buffer); vaddr <buffer + size; vaddr += PGSIZE)
      {
        spte = find_page_by_vaddr(supt, vaddr);
        frame_set_is_evict(spte->paddr, false);
      }

      lock_release(&memory_lock);
      return;
    }
    f->eax = -1;
    lock_release(&memory_lock);
    return ;   
  }
}

void
sys_filesize(int fd_, struct intr_frame *f)
{
  lock_acquire(&memory_lock);
  struct filedescriptor *fd = find_fd(fd_);

  if(fd != NULL)
  {
    f->eax = file_length(fd->f);
    lock_release(&memory_lock);
    return;
  }
  f->eax=-1;
  lock_release(&memory_lock);
}

void
sys_remove(char *name, struct intr_frame *f)
{
  check_memory_byte_by_byte(name,sizeof(name));
  lock_acquire(&memory_lock);
  f->eax = filesys_remove(name);
  lock_release(&memory_lock);
}

void
sys_seek(int fd_, int cnt, struct intr_frame *f UNUSED)
{
  lock_acquire(&memory_lock);
  struct filedescriptor *fd = find_fd(fd_);

  if(fd != NULL)
  {
    file_seek(fd->f,cnt);
    lock_release(&memory_lock);
    return;
  }
  lock_release(&memory_lock);
}

void 
sys_tell(int fd_,struct intr_frame *f)
{
  lock_acquire(&memory_lock);
  struct filedescriptor *fd = find_fd(fd_);

  if(fd != NULL)
  {
    f->eax=file_tell(fd->f);
    lock_release(&memory_lock);
    return;
  }
  f->eax=-1;
  lock_release(&memory_lock);
}

void sys_mmap(int fd, void *buffer, struct intr_frame * f)
{
  if (buffer == NULL || pg_ofs(buffer) != 0) goto END;
  if (fd < 2) goto END; 

  struct thread *curr = thread_current();
  lock_acquire (&memory_lock);

  struct file *file = NULL;
  struct filedescriptor* fd_ = find_fd(fd);
  if(fd_ && fd_->f) 
  {
    file = file_reopen (fd_->f);
  }
  if(file == NULL) goto END;

  size_t file_size = file_length(file);
  if(file_size == 0) goto END;

  size_t ofs;
  for (ofs = 0; ofs < file_size; ofs += PGSIZE) 
  {
    void *addr = buffer + ofs;
    if (find_page_by_vaddr(curr->supt, addr)) goto END; 
  }

  for (ofs = 0; ofs < file_size; ofs += PGSIZE) 
  {
    void *addr = buffer + ofs;
    size_t read_bytes;

    if((ofs + PGSIZE) < file_size)
      read_bytes = PGSIZE; 
    else
     read_bytes = file_size - ofs;

    size_t zero_bytes = PGSIZE - read_bytes;
    install_frame_by_file(curr->supt, file, addr, ofs, read_bytes, zero_bytes, true);
  }

  int mid;
  if (list_empty(&curr->mmaped_list)) 
  {
    mid = 1;
  }
  else 
  {
    mid = list_entry(list_back(&curr->mmaped_list), struct mmap_str, elem)->id + 1;
  }
  struct mmap_str *mmap_chunk = (struct mmap_str*) malloc(sizeof(struct mmap_str));
  mmap_chunk->addr = buffer;
  mmap_chunk->file_size = file_size;
  mmap_chunk->id = mid;
  mmap_chunk->file = file;
  list_push_back (&curr->mmaped_list, &mmap_chunk->elem);
  lock_release (&memory_lock);
  f->eax = mid;
  return;

END:
  lock_release (&memory_lock);
  f->eax =  -1;
  return;
}

void sys_munmap(int mid)
{
  struct thread *curr = thread_current();
  struct mmap_str *mmap_chunk = find_mmap_str(curr, mid);
  void *addr;
  if(mmap_chunk == NULL) 
  { 
    PANIC("[MUNMAP]CANNOT FIND MMAP");
    return;
  }
  lock_acquire (&memory_lock);  
  {
    size_t ofs, file_size = mmap_chunk->file_size, bytes;
    for(ofs = 0; ofs < file_size; ofs += PGSIZE) 
    {
       addr = mmap_chunk->addr + ofs;
       if((ofs + PGSIZE) < file_size)
        bytes = PGSIZE;
       else
        bytes = file_size - ofs;
       syscall_munmap_help(curr->supt, curr->pagedir, addr, mmap_chunk->file, ofs, bytes);
    }
    list_remove(& mmap_chunk->elem);
    file_close(mmap_chunk->file);
    free(mmap_chunk);
  }
  lock_release (&memory_lock);
}



static struct filedescriptor * find_fd(int fd_)
{
  struct thread *t = thread_current();
  struct filedescriptor *fd = NULL;

  if(!list_empty(&t->fd))
  {
    for(struct list_elem *tmp = list_front(&t->fd); tmp != list_tail(&t->fd); tmp = list_next(tmp))
    {
      fd = list_entry(tmp, struct filedescriptor, elem);
      if(fd->fd_num == fd_)
        return fd;
    }
  }
  return NULL;
}

static struct mmap_str*
find_mmap_str(struct thread *t, int mid)
{
  struct list_elem *elem;

  if (! list_empty(&t->mmaped_list)) {
    for(elem = list_begin(&t->mmaped_list);
        elem != list_end(&t->mmaped_list); elem = list_next(elem))
    {
      struct mmap_str *mmap = list_entry(elem, struct mmap_str, elem);
      if(mmap->id == mid) 
      {
        return mmap;
      }
    }
  }

  return NULL; // not found
}