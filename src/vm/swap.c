#include "vm/swap.h"
#include <stdio.h>
#include "devices/block.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "lib/kernel/bitmap.h"
#include "vm/page.h"

static struct block *swap;
static struct swaptable swaptable;
static block_sector_t swap_size;

void swap_init()
{
  swap = block_get_role(BLOCK_SWAP);
  swap_size = block_size(swap);
  swaptable.used_map = bitmap_create(swap_size);
  lock_init(&swaptable.lock);
}

block_sector_t alloc_swap()
{
  lock_acquire(&swaptable.lock);

  struct bitmap *b = swaptable.used_map;
  block_sector_t sector = bitmap_scan_and_flip(b, 0, PGSIZE / BLOCK_SECTOR_SIZE, false);

  lock_release(&swaptable.lock);
  if (sector == BITMAP_ERROR)
    PANIC("swap partition is FULL!\n");
    
  return sector;
}

void free_swap(block_sector_t sector)
{
  lock_acquire(&swaptable.lock);

  struct bitmap *b = swaptable.used_map;
  ASSERT(bitmap_scan(b, sector, 8, true) == sector);
  bitmap_set_multiple(b, sector, 8, false);

  lock_release(&swaptable.lock);
}

void swap_write_page(char *addr, block_sector_t sector)
{
  lock_acquire(&swaptable.lock);

  for (unsigned i = 0; i < PGSIZE / BLOCK_SECTOR_SIZE; i++)
  {
    block_write(swap, sector + i, addr + BLOCK_SECTOR_SIZE * i);
    //printf("write %p to sector %d success %d/8\n",addr + BLOCK_SECTOR_SIZE * i, sector + i, i);
  }

  lock_release(&swaptable.lock);
}

void swap_read_page(char *addr, block_sector_t sector)
{
  lock_acquire(&swaptable.lock);

  for (unsigned i = 0; i < PGSIZE / BLOCK_SECTOR_SIZE; i++)
    block_read(swap, sector + i, addr + BLOCK_SECTOR_SIZE * i);

  lock_release(&swaptable.lock);
}
