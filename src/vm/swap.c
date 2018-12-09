#include "vm/swap.h"
#include <stdio.h>
#include "devices/block.h"
#include "threads/synch.h"
#include "lib/kernel/bitmap.h"

static struct block *swap;
static struct swaptable stable;
static block_sector_t swap_size;

void swap_init()
{
  swap = block_get_role(BLOCK_SWAP);
  swap_size = block_size(swap);
  stable.used_map = bitmap_create(swap_size);
}

block_sector_t alloc_swap()
{
  lock_acquire(&stable.lock);

  struct bitmap *b = stable.used_map;
  block_sector_t sector = bitmap_scan_and_flip(b, 0, swap_size, 8);

  lock_release(&stable.lock);
  return sector;
}
void swap_write(block_sector_t sector)
{

}
