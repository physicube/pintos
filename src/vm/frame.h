#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <debug.h>
#include <stdint.h>
#include <stdbool.h>
#include "vm/page.h"
#include "lib/kernel/hash.h"


uint32_t frame_hash(const struct hash_elem *p_, void *aux UNUSED);
bool frame_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);
uint32_t *alloc_frame(struct spte *spte);
uint32_t *evict_frame();
void frame_init();
struct fte *lookup_frame(const void *addr);

struct fte 
{
  uint32_t *addr;
  struct spte *spte;

  bool accessed;
  bool dirty;

  struct hash_elem hash_elem;
};

#endif