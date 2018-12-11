#include <hash.h>
#include <list.h>
#include "threads/malloc.h"
#include <stdio.h>
#include "threads/palloc.h"
#include "lib/kernel/hash.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "threads/thread.h"
#include "lib/kernel/list.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"

void frame_init()
{
  lock_init(&frame_lock);
  hash_init(&frame_map, frame_hash_func, frame_less_func, NULL);
  list_init(&frame_list_eviction);
}

static void get_and_set_swap_idx(struct SPTABLE * supt, void *vaddr)
{
    struct SPTE * supte = find_page_by_vaddr(supt, vaddr);
    if(!supte)
    {
        printf("something was wrong in get_and_set_swap_idx. :p\n");
        NOT_REACHED();
    }
    else
    {
        supte->status = ON_SWAP;
        supte->paddr = NULL;
        supte->swap_idx = swap_write_block(vaddr);
    }
}

void *
frame_allocate(enum palloc_flags flags, void *vaddr)
{
  lock_acquire(&frame_lock);

  void *frame_page_palloc = NULL;
  if (!(frame_page_palloc = palloc_get_page(PAL_USER | flags)))
  {
    struct fte *victim = choose_evict(thread_current()->pagedir);
    pagedir_clear_page(victim->t->pagedir, victim->vaddr);
    calculate_and_set_dirty_bit(false, victim);
    get_and_set_swap_idx(victim->t->supt, vaddr); // in swap.c
    frame_free_external(victim->paddr, true); 
    frame_page_palloc = palloc_get_page(PAL_USER | flags); // now, you can allocate new frame.
  }

  struct fte *frame = malloc(sizeof(struct fte));
  frame->vaddr = vaddr;
  frame->paddr = frame_page_palloc;
  frame->is_evict = true;
  frame->t = thread_current();

  hash_insert(&frame_map, &frame->hash_elem);
  list_push_back(&frame_list_eviction, &frame->list_elem);
  lock_release(&frame_lock);
  return frame_page_palloc;
}

void frame_free_external(void *paddr, bool mode)
{
  lock_acquire(&frame_lock);
  frame_free_internal(paddr, mode);
  lock_release(&frame_lock);
}

void frame_free_internal(void *paddr, bool delete_flag)
{
  struct fte tmp_fte;
  tmp_fte.paddr = paddr;

  struct hash_elem *h = hash_find(&frame_map, &tmp_fte.hash_elem);
  struct fte *f;
  f = hash_entry(h, struct fte, hash_elem);

  hash_delete(&frame_map, &f->hash_elem);
  list_remove(&f->list_elem);

  // Free resources
  if (delete_flag)
    palloc_free_page(paddr);
  free(f);
}

struct fte * choose_evict(uint32_t *pagedir)
{
  size_t cnt;
  struct fte *eviction = NULL;
  for (cnt = 0; cnt <= 2 * cnt; cnt ++)
  {
    if (!evict_p || evict_p == list_end(&frame_list_eviction))
    {
      evict_p = list_begin(&frame_list_eviction);
    }
    else
    {
      evict_p = list_next(evict_p); // get next list.
    }
    eviction = list_entry(evict_p, struct fte, list_elem);
    if (eviction->is_evict) continue; // do not evict accesing frame(swap, file ..)
    else if (pagedir_is_accessed(pagedir, eviction->vaddr))
    { // give second chance.
      pagedir_set_accessed(pagedir, eviction->vaddr, false);
      continue;
    }
    return eviction;
  }
    printf("You cannot come here! maybe something was wrong. :p\n");
    NOT_REACHED();
}

void
frame_set_is_evict(void *paddr, bool value)
{
  lock_acquire(&frame_lock);
  struct fte tmp_fte;
  struct fte *fte_tmp;

  tmp_fte.paddr = paddr;
  hash_tmp = hash_find(&frame_map, &tmp_fte.hash_elem);
  fte_tmp = hash_entry(hash_tmp, struct fte, hash_elem);
  fte_tmp->is_evict = value;

  lock_release(&frame_lock);
}


void 
calculate_and_set_dirty_bit(bool dirty_bit, struct fte * fte)
{
    dirty_bit = dirty_bit || pagedir_is_dirty(fte->t->pagedir, fte->vaddr) || pagedir_is_dirty(fte->t->pagedir, fte->paddr); // for vaddr
    struct SPTE * spte = find_page_by_vaddr(thread_current()->supt, fte->vaddr);
    if(!spte)
    {
        printf("something was wrong in set_dirty_supt. :p\n");
        NOT_REACHED();
    }
    else
    {
        spte->dirty = spte->dirty || dirty_bit;
    }
}



static unsigned frame_hash_func(const struct hash_elem *elem, void *aux UNUSED)
{
  struct fte *entry = hash_entry(elem, struct fte, hash_elem);
  return hash_bytes(&entry->paddr, sizeof entry->paddr);
}
static bool frame_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  struct fte *a_entry = hash_entry(a, struct fte, hash_elem);
  struct fte *b_entry = hash_entry(b, struct fte, hash_elem);
  return a_entry->paddr < b_entry->paddr;
}
