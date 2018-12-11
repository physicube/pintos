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
#include "lib/kernel/list.h"
#include "devices/input.h"
#include "vm/swap.h"
#include "threads/malloc.h"
#include "vm/page.h"

static void syscall_handler (struct intr_frame *);
int read_phys_mem(unsigned char *addr);
struct lock memory_lock;
bool check_validate(void *addr);
void check_memory_byte_by_byte(void * addr, size_t size);
void read_mem(void *f, unsigned char *esp, int num, bool is_pointer);
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
void sys_munmap(int, struct intr_frame *);

static struct filedescriptor * find_fd(int fd_);
static int give_mpid(struct list * mlist);
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
}

bool check_validate(void *addr)
{
  if(addr >= 0x8048000 && is_user_vaddr(addr))
    return true;
  return false;
}

void read_mem(void *f, unsigned char *esp, int num, bool is_pointer)
{
  
   for(int i = 0; i < num; i++) 
   { 
    if(check_validate(esp + i)) 
      *(char *)(f + i) = read_phys_mem(esp + i) & 0xff; 
    else 
      sys_exit(-1,NULL); 
   }
   uint32_t *pointer = *(uint32_t *)f;
   if (is_pointer && is_user_vaddr(pointer))
   {
     if (lookup_spte(pointer))
      alloc_user_pointer(pointer);
   }
}

static void
syscall_handler (struct intr_frame *f) 
{
  int syscall_number;
  void *esp = f->esp;
  //printf("syscall called!\n");
  if(!check_validate(esp) && !check_validate(esp+4) && ! check_validate(esp+8) && !check_validate(esp+12))
    sys_exit(-1,NULL);
  

  read_mem(&syscall_number, esp, sizeof(syscall_number), false);
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
      read_mem(&exit_code, esp+4, sizeof(exit_code), false);
      sys_exit(exit_code,f);
      break;
    }
    case SYS_EXEC: 
    { 
      void *cmd;
      read_mem(&cmd, esp+4, sizeof(cmd), true);
      sys_exec(cmd,f);
      break;
    }
    case SYS_WAIT:
    { 
      int tid;
      read_mem(&tid,esp+4, sizeof(tid), false);
      sys_wait(tid,f);
      break;
    }
    case SYS_CREATE: 
    {
      char *name;
      size_t size;
      read_mem(&name, esp+4, sizeof(name), true);
      read_mem(&size, esp+8, sizeof(size), false);
      sys_create(name,size,f);
      break;
    }
    case SYS_REMOVE: 
    {
      char *name;
      read_mem(&name,esp+4, sizeof(name), true);
      sys_remove(name,f);
      break;
    }
    case SYS_OPEN: 
    {
      char *name;
      read_mem(&name, esp+4, sizeof(name), true);
      sys_open(name,f);
      break;
    }
    case SYS_FILESIZE: 
    {
      int fd;
      read_mem(&fd,esp+4, sizeof(fd), false);
      sys_filesize(fd,f);
      break;
    }
    case SYS_READ:
    {
      int fd, size;
      void *buffer;
      read_mem(&fd,esp+4, sizeof(fd), false);
      read_mem(&buffer, esp+8, sizeof(fd), true);
      read_mem(&size, esp+12, sizeof(fd), false);
      sys_read(fd,buffer,size,f);
      break;
    }
    case SYS_WRITE: 
    { 
      int fd, size;
      void *buffer;
      read_mem(&fd,esp+4, sizeof(fd), false);
      read_mem(&buffer, esp+8, sizeof(buffer), true);
      read_mem(&size, esp+12, sizeof(size), false);
      sys_write(fd,buffer, size, f);
      break;
    }
    case SYS_SEEK: 
    {
      int fd, cnt;
      read_mem(&fd,esp+4, sizeof(fd), false);
      read_mem(&cnt,esp+8, sizeof(cnt), false);
      sys_seek(fd, cnt, f);
      break;
    }
    case SYS_TELL: 
    {
      int fd;
      read_mem(&fd,esp+4, sizeof(fd), false);
      sys_tell(fd,f);
      break;
    }
    case SYS_CLOSE: 
    {
      int fd;
      read_mem(&fd, esp+4, sizeof(fd), false);
      sys_close(fd,f);
      break;
    }
    case SYS_MMAP:
    {
      int fd;
      void *buffer;
      read_mem(&fd, esp+4, sizeof(fd), false);
      read_mem(&buffer, esp+8, sizeof(buffer), true);
      sys_mmap(fd, buffer, f);
      break;
    }
    case SYS_MUNMAP:
    {
      int mid;
      read_mem(&mid, esp+4, sizeof(mid), false);
      sys_munmap(mid,f);
      break;
    }
    default:
    {
      int exit_code;
      read_mem(&exit_code, esp+4, sizeof(exit_code), false);
      sys_exit(exit_code, NULL);
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
        f->eax = file_write(fd->f, buffer, size);
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
  
  fd = (struct filedescriptor *)malloc(sizeof(struct filedescriptor));
  if(fd == NULL)
  {
    free(fd);
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
    struct filedescriptor *fd = find_fd(fd_);
    if (fd == NULL)
      return;
    if(t->tid == fd->master->tid) // check master thread.
    {
      file_close(fd->f);
      list_remove(&(fd->elem));
      free(fd);
    }
    lock_release(&memory_lock);
  }
}

void
sys_read(int fd_, void * buffer, int size, struct intr_frame *f)
{
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
      f->eax = file_read(fd->f, buffer,size);
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

void sys_mmap(int fd_, void* buffer, struct intr_frame *f)
{
  struct thread *t = thread_current();
  struct mmap_str * mmap_str = NULL;
  struct filedescriptor * fd = NULL;
  size_t file_size = 0;
  size_t ofs = 0;

  lock_acquire(&memory_lock);

  if(fd_ < 2 || !buffer || pg_ofs(buffer) != 0)
    goto END;
  if(!(fd = find_fd(fd_)))
    goto END;
  if((file_size = file_length(fd->f)) <= 0)
    goto END;
  
  for(ofs = 0; ofs < file_size; ofs += PGSIZE)
  {
    if(!(lookup_spte(buffer + ofs)) || !pagedir_get_page(t->pagedir, buffer+ofs));
      goto END; // pages are not enough
  }

  void * addr = NULL;
  size_t read_b, zero_b;
  for(ofs = 0; ofs < file_size; ofs += PGSIZE)
  {
    addr = buffer + ofs;
    if(ofs + PGSIZE < file_size)
      read_b = PGSIZE;
    else
      read_b = file_size - ofs;
    zero_b = PGSIZE - read_b;

    struct spte *spte = (struct spte*)malloc(sizeof(struct spte));
    spte->vaddr = buffer;
    spte->fte = NULL;
    spte->type = SPTE_FILE;
    spte->writable = true;
    spte->file = fd->f;
    spte->ofs = ofs;
    spte->size = read_b;

    struct hash_elem * prev = hash_insert(&t->sptable, &spte->hash_elem);
    if(prev != NULL)
    {
      free(spte);
      goto END;
    }
    //counter++;
  }
  mmap_str = (struct mmap_str *)malloc(sizeof(mmap_str));
  mmap_str->file = fd->f;
  mmap_str->file_size = file_size;
  mmap_str->id = give_mpid(&t->mlist);
  mmap_str->uaddr = buffer;
  //mmap_str->cnt = counter;
  list_push_back(&t->mlist, &mmap_str->elem);
  lock_release(&memory_lock);
  f->eax = mmap_str->id;
  //printf("[MMAP] created mmap_str addr : %p, file_addr : %p\n",mmap_str, mmap_str->file);
  return;

  END:
  f->eax = -1;
  lock_release(&memory_lock);
  return;
}

void sys_munmap(int mid, struct intr_frame *f)
{
  struct thread * t = thread_current();
  struct mmap_str * mmap_ = NULL;
  struct list * list = &t->mlist;

  if(!list_empty(list))
  {
    struct list_elem * elem;
    for(elem = list_begin(list); elem != list_end(list); elem = list_next(elem))
    {
      mmap_ = list_entry(elem, struct mmap_str, elem);
      if(mmap_->id == mid)
      {
       // printf("[MUNMAP] mid: %d, vaddr : %p, file : %p \n",mmap_->id, mmap_->uaddr, mmap_->file);
        list_remove(elem);
        break;
      }
      mmap_ = NULL;
    }
  }
  else
    goto END;
  if(!mmap_) goto END;
  //printf("[MUNMAP] find mmap_ addr : %p, file_addr : %p\n",mmap_, mmap_->file);
  size_t cnt = mmap_->cnt;
  struct spte * spte_tmp;
  struct spte spte_find;
  struct hash_elem * tmp_elem;
  size_t ofs = 0, file_size = mmap_->file_size, byte;
  void *addr;

  lock_acquire(&memory_lock);
  for(ofs = 0; ofs < file_size; ofs += PGSIZE)
  {
    addr = mmap_->uaddr + ofs;
    byte = (ofs + PGSIZE < file_size ? PGSIZE : file_size - ofs);

    spte_find.vaddr = addr;
    tmp_elem = hash_find(&t->sptable, &spte_find.hash_elem);
    if(tmp_elem == NULL)
    {
      PANIC("CANNOT HAPPEND!");
    }
    spte_tmp = hash_entry(tmp_elem, struct spte, hash_elem);
    //printf("[MUNMAP] what is the type? : %d\n",spte_tmp->type);
    switch(spte_tmp->type)
    {
      case SPTE_LIVE:
      {
        struct spte * spte_tmp = lookup_spte(addr);
        spte_tmp->fte->pinned = true;
        if(pagedir_is_dirty(t->pagedir, spte_tmp->vaddr) || pagedir_is_dirty(t->pagedir, spte_tmp->fte->addr))
        {
          file_write_at(mmap_->file, spte_tmp->vaddr, byte, ofs);
        }
        //printf("[MUNMAP] fte->addr : %p\n", spte_tmp->fte->addr);
        palloc_free_page(spte_tmp->fte->addr);
        free(spte_tmp->fte);
        pagedir_clear_page(t->pagedir, spte_tmp->vaddr);
        break;
      }
      case SPTE_FILE:
      {
        break;
      }
      case SPTE_SWAP:
      {

      }
      default:
        PANIC("How can you come here?");
    }
  }

  file_close(mmap_->file);
  free(mmap_);
  lock_release(&memory_lock);

  END:
  return;
}



static int give_mpid(struct list * mlist)
{
  if(list_size(mlist) == 0)
  {
    return 1;
  }
  else
  {
    return list_entry(list_back(mlist), struct mmap_str, elem)->id+1;
  }
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


