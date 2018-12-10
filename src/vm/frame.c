#include "vm/frame.h"
#include <stdio.h>
#include "devices/block.h"
#include "userprog/pagedir.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "lib/kernel/hash.h"
#include "lib/string.h"
#include "vm/page.h"
#include "vm/swap.h"

/* ftable is global */
static struct lock frame_lock;
static struct hash_elem *evict_pin = NULL; /* check from this */

uint32_t frame_hash(const struct hash_elem *p_, void *aux UNUSED)
{
  const struct fte *f = hash_entry(p_, struct fte, hash_elem);
  return hash_bytes (&f->addr, sizeof f->addr);
}

bool frame_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED)
{
  const struct fte *a = hash_entry(a_, struct fte, hash_elem);
  const struct fte *b = hash_entry(b_, struct fte, hash_elem);

  return a->addr < b->addr;
}

void frame_init(void)
{
  lock_init(&frame_lock);
  hash_init(&ftable, frame_hash, frame_less, NULL);
}

/* allocate frame of given supplement table entry */
uint32_t *alloc_frame(struct spte *spte)
{
  lock_acquire(&frame_lock);

  uint32_t *new_frame = palloc_get_page(PAL_USER);
  struct fte* fte;

  //printf("%d frame allocated %p\n", hash_size(&ftable), new_frame);
  if (!new_frame)
  {
    fte = evict_frame();
    new_frame = fte->addr;
  }
  else
  {
    fte = malloc(sizeof(struct fte));

    fte->addr = new_frame;
    hash_insert(&ftable, &fte->hash_elem);

  }

  //printf("[FRAME ALLOC] spte vaddr : %p, fte->addr: %p\n",spte->vaddr, fte->addr);
  fte->spte = spte;
  fte->accessed = true;
  if (spte->writable == false)
  {

  }
  fte->pinned = false;
  fte->magic = 0xdeadbeef;
  spte->fte = fte;

  switch(spte->type)
  {
    case SPTE_FILE:
    {
      file_read_at(spte->file, new_frame, spte->size, spte->ofs);
      memset(new_frame + spte->size, 0, PGSIZE - spte->size);
      break;
    }
    case SPTE_SWAP:
    {
      swap_read_page(new_frame, spte->sector);
      free_swap(spte->sector);
      break;
    }
    default:
      memset(new_frame, 0, PGSIZE);
  }
  //printf("memory copy done\n");
  spte->type = SPTE_LIVE;

  lock_release(&frame_lock);

  return fte;
}

struct fte *evict_frame(void)
{
  //printf("evict frame called\n");

  struct hash_iterator iter;
  struct thread *cur = thread_current();
  struct fte *fte;
  struct spte *spte;

  hash_first(&iter, &ftable);
  if (!evict_pin || !hash_find(&ftable, evict_pin))
  {
    evict_pin = hash_next(&iter);
  }
  else
  {
    while (hash_next(&iter) != evict_pin){}
  }
  while (true)
  {
    fte = hash_entry(hash_cur(&iter), struct fte, hash_elem);
    spte = fte->spte;
    //printf("check frame..%p\n", fte->addr);
    //printf("check vaddr %p\n", fte->magic);
    fte->accessed = pagedir_is_accessed(cur->pagedir, spte->vaddr);

    pagedir_set_accessed(cur->pagedir, spte->vaddr, false);

    /* if end of hash table, then return to start */
    if (!hash_next(&iter))
    {
      hash_first(&iter, &ftable);
      hash_next(&iter);
    }

    if (spte->writable && !fte->accessed && !fte->pinned)
    {
      fte->pinned = true;
      block_sector_t sector = alloc_swap();
      //printf("empty sector %d\n", sector);
      swap_write_page(fte->addr, sector);
      //printf("write to swap finished\n");

      spte->type = SPTE_SWAP;
      spte->sector = sector;
      spte->fte = NULL;
      pagedir_clear_page(cur->pagedir, spte->vaddr);

      fte->spte = NULL;
      fte->pinned = false;
      break;
    }
  }
  evict_pin = hash_cur(&iter);
  //printf("frame addr %p evicted\n", fte->addr);
  return fte;
}

void free_frame(struct spte *spte)
{
  struct fte* fte = spte->fte;
  
  palloc_free_page(fte->addr);
  spte->fte = NULL;
  free(fte);
}

/* find frame with given frame addr
in pintos reference guide */
struct fte *lookup_frame(const void *addr)
{
  lock_acquire(&frame_lock);
  struct fte f;
  struct hash_elem *e;

  f.addr = addr;
  e = hash_find (&ftable, &f.hash_elem);
  lock_release(&frame_lock);

  return e != NULL ? hash_entry (e, struct fte, hash_elem) : NULL;
}