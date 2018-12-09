#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "devices/block.h"
#include "lib/kernel/hash.h"
#include "vm/frame.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

#define SPTE_LIVE 0
#define SPTE_FILE 1
#define SPTE_SWAP 2

struct spte
{
  void *vaddr;
  struct fte *fte;
  uint32_t type; /* file, swap etc */
  bool writable;
  bool pinned;

  /* read from file (type == SPTE_FILE) */
  struct file *file;
  off_t ofs;
  uint32_t size;

  /* read from swap (type == SPTE_SWAP)*/
  block_sector_t sector;

  /* member of hash table spt */
  struct hash_elem hash_elem;
};

uint32_t spte_hash(const struct hash_elem *p_, void *aux UNUSED);
bool spte_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);
void sptable_init();
void spte_free(struct hash_elem *e, void *aux);
void load_page(void *vaddr);
struct spte *lookup_spte(const void *vaddr);

#endif