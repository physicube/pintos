#include "vm/frame.h"
#include <stdio.h>
#include "devices/block.h"
#include "userprog/pagedir.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "lib/kernel/hash.h"
#include "lib/string.h"
#include "vm/page.h"
#include "vm/swap.h"

/* ftable is global */
static struct lock frame_lock;
static struct hash ftable;

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

void frame_init()
{
  lock_init(&frame_lock);
  hash_init(&ftable, frame_hash, frame_less, NULL);
}

/* allocate frame of given supplement table entry */
uint32_t *alloc_frame(struct spte *spte)
{
  lock_acquire(&frame_lock);

  uint32_t *new_frame = palloc_get_page(PAL_USER);
  //printf("new frame allocated %p\n", new_frame);
  if (new_frame == NULL)
  {
    new_frame = evict_frame();
    if (new_frame == NULL)
      printf("eviction failed!\n");
  }
  struct fte* fte = malloc(sizeof(struct fte));

  fte->addr = new_frame;
  fte->spte = spte;
  fte->accessed = false;
  fte->dirty = false;
  hash_insert(&ftable, &fte->hash_elem);

  spte->fte = fte;
  if (spte->type == SPTE_FILE)
  {
    file_read_at(spte->file, new_frame, spte->size, spte->ofs);
    memset(new_frame + spte->ofs + spte->size, 0, PGSIZE - spte->size);
  }
  
  lock_release(&frame_lock);
  return new_frame;
}

uint32_t *evict_frame()
{
  return NULL;
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