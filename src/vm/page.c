#include "vm/page.h"
#include <stdio.h>
#include "threads/thread.h"
#include "threads/palloc.h"
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
void load_page(void *vaddr)
{
  struct thread *cur = thread_current();
  struct hash *sptable = &cur->sptable;
  ASSERT(!pagedir_get_page(cur->pagedir, vaddr));


  struct spte *spte = lookup_spte(vaddr);
  if (spte == NULL)
  {
    spte = malloc(sizeof(struct spte));
    spte->vaddr = vaddr;
    spte->writable = true;
    spte->type = SPTE_LIVE;
    spte->ofs = 0;
    spte->size = PGSIZE;

    hash_insert(&cur->sptable, &spte->hash_elem);
  }

  struct fte *fte = alloc_frame(spte);
  if (fte == NULL)
  {
    printf("frame alloc failed\n");
    PANIC("frame alloc failed\n");
  }
  spte->fte = fte;

  //printf("map %p to %p\n", vaddr, &fte->addr);
  install_page(vaddr, &fte->addr, spte->writable);
  spte->type = SPTE_LIVE;

  sema_up(&cur->page_sema);
}

/* find spte with given spte addr
in pintos reference guide */
struct spte *lookup_spte(const void *vaddr)
{
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
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

/* hash_action_func */
void spte_free(struct hash_elem *e, void *aux)
{
  const struct spte *spte = hash_entry(e, struct spte, hash_elem);
  free(spte);
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