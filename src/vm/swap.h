#ifndef VM_SWAP_H
#define VM_SWAP_H
#include "threads/vaddr.h"
#include "devices/block.h"
#include <bitmap.h>

typedef uint32_t swap_index_t;
static const size_t NUM_OF_SECTORS_PER_PAGE = PGSIZE / BLOCK_SECTOR_SIZE;

static struct block *swap_blk;
static struct bitmap *swap_bitmap;
static size_t swap_size;

void swap_init (void);
size_t swap_write_block (void *paddr); // swap out
void swap_read_block (size_t swap_idx, void *page); // swap in
void swap_free (size_t swap_idx);

#endif
