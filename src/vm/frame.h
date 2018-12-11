#ifndef VM_FRAME_H
#define VM_FRAME_H
#include <hash.h>
#include <debug.h>
#include <stdint.h>
#include <stdbool.h>
#include "vm/page.h"
#include "lib/kernel/hash.h"

struct hash ftable;

uint32_t frame_hash(const struct hash_elem *p_, void *aux UNUSED);
bool frame_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);
struct fte *alloc_frame(struct spte *spte);
struct fte *evict_frame();
void free_frame(struct fte *fte);
void frame_init();
struct fte *lookup_frame(const void *addr);

struct fte 
{
  uint32_t *addr;
  struct spte *spte;

  bool accessed;
  bool pinned;

  uint32_t magic;
  struct hash_elem hash_elem;
};

#endif