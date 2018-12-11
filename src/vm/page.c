#include "vm/page.h"
#include <stdio.h>
#include "threads/thread.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"
#include "lib/kernel/hash.h"

static bool install_page (void *upage, void *kpage, bool writable);

/* initialize supplement page table */
void sptable_init()
{
  struct thread *cur = thread_current();
  sema_init(&cur->page_sema, 0);
  hash_init(&cur->sptable, spte_hash, spte_less, NULL);
}

/* allocate new frame for vaddr and map it */
bool load_page(void *vaddr, bool create)
{
  //printf("load page called\n");
  struct thread *cur = thread_current();
  struct hash *sptable = &cur->sptable;
  bool writable = true;
  ASSERT(!pagedir_get_page(cur->pagedir, vaddr));
  ASSERT(is_user_vaddr(vaddr));
  struct spte *spte = lookup_spte(vaddr);

  if (!spte)
  {
    if (create)
    {
      spte = malloc(sizeof(struct spte));
      spte->vaddr = vaddr;
      spte->writable = true;
      spte->type = SPTE_LIVE;
      spte->ofs = 0;
      spte->magic = 0xdeadbeef;
      spte->size = PGSIZE;
      hash_insert(&cur->sptable, &spte->hash_elem);
      //printf("new spte created\n");
    }
    else
      return false;
  }
  //printf("get spte finished!\n");
  struct fte *fte = (struct fte*)alloc_frame(spte);
  if (!fte)
  {
    //printf("frame alloc failed\n");
    PANIC("frame alloc failed\n");
  }
  //printf("frame alloc done\n");
  spte->fte = fte;
  spte->type = SPTE_LIVE;
  spte->is_load = true;

  //printf("map %p to %p\n", vaddr, fte->addr);
  install_page(vaddr, fte->addr, spte->writable);
  
  sema_up(&cur->page_sema);






  return true;
}

void alloc_user_pointer(void *vaddr)
{
  //printf("alloc_user_pointer called\n");
  struct thread *cur = thread_current();
  ASSERT(is_user_vaddr(vaddr));

  if (!pagedir_get_page(cur->pagedir, vaddr))
  {
    load_page(vaddr, false);
    sema_down(&cur->page_sema);
  }
}


/* find spte with given spte addr
in pintos reference guide */
struct spte *lookup_spte(const void *vaddr)
{
  //printf("lookup spte called\n");
  struct thread *cur = thread_current();

  struct spte spte;
  struct hash_elem *e;
  spte.vaddr = vaddr;
  e = hash_find (&cur->sptable, &spte.hash_elem);

  return e != NULL ? hash_entry (e, struct spte, hash_elem) : NULL;
}

static bool
install_page (void *upage, void *kpage, bool writable)
{
  //printf("install page called\n");
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

/* hash_action_func */
void spte_free(struct hash_elem *e, void *aux)
{
  struct spte *spte = hash_entry(e, struct spte, hash_elem);
  struct fte *fte = spte->fte;
  if (fte)
  {
    if (fte->magic == 0xdeadbeef)
      free_frame(spte);
  }
  pagedir_clear_page(thread_current()->pagedir, spte->vaddr);
  free(spte);
}
void sptable_free(struct hash *sptable)
{
  struct hash_iterator iter;
  hash_first(&iter, sptable);
  while (hash_next(&iter))
  {
    struct spte *spte = hash_entry(hash_cur(&iter), struct spte, hash_elem);
    struct fte *fte = spte->fte;
    if (fte)
    {
      if (fte->magic == 0xdeadbeef)
        free_frame(spte);
    }
    if (!pagedir_get_page(thread_current()->pagedir, spte->vaddr))
      pagedir_clear_page(thread_current()->pagedir, spte->vaddr);
    free(spte);
  }
}

/* hash function */
uint32_t spte_hash(const struct hash_elem *p_, void *aux UNUSED)
{
  const struct spte *spte = hash_entry(p_, struct spte, hash_elem);
  return hash_bytes (&spte->vaddr, sizeof spte->vaddr);
}

/* hash less function */
bool spte_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED)
{
  const struct spte *a = hash_entry(a_, struct spte, hash_elem);
  const struct spte *b = hash_entry(b_, struct spte, hash_elem);

  return a->vaddr < b->vaddr;
}