#include <hash.h>
#include <string.h>
#include <stdio.h>
#include "vm/page.h"
#include "userprog/pagedir.h"
#include "lib/kernel/hash.h"
#include "vm/frame.h"
#include "filesys/file.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/thread.h"

struct SPTABLE*
suptable_create (void)
{
  struct SPTABLE *supt = (struct SPTABLE *) malloc(sizeof(struct SPTABLE));
  hash_init (&supt->page_table, hash_func, less_func, NULL);
  return supt;
}

void
free_page (struct SPTABLE *supt)
{
  hash_destroy (&supt->page_table, free_func);
  free (supt);
}

bool
install_frame (struct SPTABLE *supt, void *vaddr, void *paddr, bool mode)
{
  struct SPTE *spte;
  spte = (struct SPTE *) malloc(sizeof(struct SPTE));

  if(mode)
  {
    spte->status = SPTE_FRAME;
    spte->dirty = false;
    spte->vaddr = vaddr;
    spte->paddr = paddr;
    spte->swap_idx = -1;
  }
  else
  {
    spte->status = ZERO;
    spte->dirty = false;
    spte->vaddr = vaddr;
    spte->paddr = NULL;
  }

  struct hash_elem *prev_hash_elem;
  prev_hash_elem = hash_insert (&supt->page_table, &spte->hash_elem);
  if (!prev_hash_elem) 
    return true;
  else 
  {
    free (spte);
    return false;
  }
}


bool
install_frame_by_file (struct SPTABLE *supt, struct file * file, void *vaddr, size_t ofs, uint32_t read_b, uint32_t zero_b, bool writable)
{
  struct SPTE *spte = (struct SPTE *) malloc(sizeof(struct SPTE));

  spte->vaddr = vaddr;
  spte->status = LOAD_FILESYS;
  spte->read_b = read_b;
  spte->zero_b = zero_b;
  spte->writable = writable;
  spte->file = file;
  spte->ofs = ofs;
  spte->dirty = false;
  spte->paddr = NULL;

  struct hash_elem *prev_hash_elem;
  prev_hash_elem = hash_insert (&supt->page_table, &spte->hash_elem);
  //printf("[PAGE.C/ frame_file] page install : vaddr : %p, status : %d , owner: %s\n", spte->vaddr, spte->status, thread_current()->name);
  if (prev_hash_elem == NULL) 
  {
    return true;
  }
}

bool
set_page_swap (struct SPTABLE *supt, void *page, unsigned swap_idx)
{
  struct SPTE *spte;
  spte = find_page_by_vaddr(supt, page);
  if(spte == NULL) 
    return false;
  else
  {
    spte->status = ON_SWAP;
    spte->swap_idx = swap_idx;
    spte->paddr = NULL;
    return true;
  }  
}

static bool load_page_from_FILESYS(struct SPTE *spte, void *paddr)
{
  file_seek (spte->file, spte->ofs);
  int n_read; 
  if(file_read (spte->file, paddr, spte->read_b) != (int)spte->read_b)
    return false;
  memset (paddr + spte->read_b, 0, spte->zero_b);
  return true;
}


bool
set_page_dirty (struct SPTABLE *supt, void *page, bool value)
{
  struct SPTE *spte = find_page_by_vaddr(supt, page);
  spte->dirty = spte->dirty || value;
  return true;
}

bool
load_page(struct SPTABLE *supt, uint32_t *pagedir, void *vaddr)
{
  bool writable = true;
  struct SPTE *spte = find_page_by_vaddr(supt, vaddr);
  if(spte == NULL)  return false;
  if(spte->status == SPTE_FRAME) return true;
  //printf("[Load page] vaddr : %p\n",vaddr);
  void *frame_mold = frame_allocate(PAL_USER, vaddr);
  if(frame_mold == NULL) return false;

  switch (spte->status)
  {
  case ZERO:
    memset (frame_mold, 0, PGSIZE);
    break;
  case SPTE_FRAME:
    break;
  case ON_SWAP:
    swap_read_block (spte->swap_idx, frame_mold);
    break;
  case LOAD_FILESYS:
    if( load_page_from_FILESYS(spte, frame_mold) == false) 
    {
      frame_free_external(frame_mold, true);
      return false;
    }
    writable = spte->writable;
    break;
  default:
    PANIC ("How can you come here?");
  }
  spte->paddr = frame_mold;
  spte->status = SPTE_FRAME;
  if(!pagedir_set_page (pagedir, vaddr, frame_mold, writable)) 
  {
    frame_free_external(frame_mold, true);
    return false;
  }

  pagedir_set_dirty (pagedir, frame_mold, false);
  frame_set_is_evict(spte->paddr, false);

  return true;
}

bool
syscall_munmap_help(struct SPTABLE *supt, uint32_t *pagedir, void *page, struct file *file, size_t ofs, size_t bytes)
{
  struct SPTE *spte = find_page_by_vaddr(supt, page);
  if (spte->status == SPTE_FRAME) 
  {
    make_frame_unvictim (supt,spte->paddr); 
  }
  
  switch (spte->status)
  {
  case SPTE_FRAME:
    if(spte->dirty || pagedir_is_dirty(pagedir, spte->vaddr) || pagedir_is_dirty(pagedir, spte->paddr))
    {
      file_write_at (file, spte->vaddr, bytes, ofs);
    }
    frame_free_external (spte->paddr, true);
    pagedir_clear_page (pagedir, spte->vaddr);
    break;
  case ON_SWAP:
    {
      if (spte->dirty || pagedir_is_dirty(pagedir, spte->vaddr) || pagedir_is_dirty(pagedir, spte->paddr)) 
      {
        void *page = palloc_get_page(0); 
        swap_read_block(spte->swap_idx, page);
        file_write_at (file, page, PGSIZE, ofs);
        palloc_free_page(page);
      }
      else 
      {
        swap_free (spte->swap_idx);
      }
    }
    break;
  case LOAD_FILESYS:
    break;

  default:
    PANIC ("HOW CAN YOU COME HERE?");
  }
  
  hash_delete(&supt->page_table, &spte->hash_elem);
  //printf("[MUNMAP] spte vaddr : %p\n",spte->vaddr);
  return true;
}


void
make_frame_unvictim(struct SPTABLE *supt, void *page)
{
  struct SPTE *spte;
  spte = find_page_by_vaddr(supt, page);
  if(spte == NULL) return;
  frame_set_is_evict(spte->paddr, true);
}

void
make_frame_victim(struct SPTABLE *supt, void *page)
{
  struct SPTE *spte = find_page_by_vaddr(supt, page);
  if (spte->status == SPTE_FRAME) 
  {
    frame_set_is_evict(spte->paddr, false);
  }
}

struct SPTE*
find_page_by_vaddr (struct SPTABLE *supt, void *page)
{
  struct SPTE spte_temp;
  spte_temp.vaddr = page;
  struct hash_elem *hash_elem = hash_find (&supt->page_table, &spte_temp.hash_elem);
  if(hash_elem == NULL) 
    return NULL;
  else
    return hash_entry(hash_elem, struct SPTE, hash_elem);
}

static unsigned
hash_func(const struct hash_elem *hash_elem, void *aux UNUSED)
{
  struct SPTE *entry = hash_entry(hash_elem, struct SPTE, hash_elem);
  return hash_int( (int)entry->vaddr );
}
static bool
less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  struct SPTE *first = hash_entry(a, struct SPTE, hash_elem);
  struct SPTE *second = hash_entry(b, struct SPTE, hash_elem);
  return first->vaddr < second->vaddr;
}
static void
free_func(struct hash_elem *hash_elem, void *aux UNUSED)
{
  struct SPTE *entry = hash_entry(hash_elem, struct SPTE, hash_elem);

  if (entry->paddr != NULL) 
  {
    frame_free_external(entry->paddr, false);
  }
  else if(entry->status == ON_SWAP) 
  {
    swap_free (entry->swap_idx);
  }

  free (entry);
}
