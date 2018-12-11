#include "threads/vaddr.h"
#include "devices/block.h"
#include <bitmap.h>
#include "vm/swap.h"

void
swap_init (void)
{
  swap_blk = block_get_role(BLOCK_SWAP);
  swap_bitmap = bitmap_create(block_size(swap_blk) / NUM_OF_SECTORS_PER_PAGE);
  bitmap_set_all(swap_bitmap, true);
}

size_t swap_write_block (void *paddr)
{
  size_t swap_idx = bitmap_scan (swap_bitmap, 0, 1, true);
  size_t idx;
  for (idx = 0; idx < NUM_OF_SECTORS_PER_PAGE; idx ++) 
  {
    block_write(swap_blk, swap_idx * NUM_OF_SECTORS_PER_PAGE + idx, paddr + (BLOCK_SECTOR_SIZE * idx));
  }
  bitmap_set(swap_bitmap, swap_idx, false);
  return swap_idx;
}

void swap_read_block (size_t swap_idx, void *page)
{
  size_t idx;
  for (idx = 0; idx < NUM_OF_SECTORS_PER_PAGE; idx ++) 
  {
    block_read (swap_blk, swap_idx * NUM_OF_SECTORS_PER_PAGE + idx, page + (BLOCK_SECTOR_SIZE * idx));
  }
  bitmap_set(swap_bitmap, swap_idx, true);
}

void
swap_free (size_t swap_idx)
{
  bitmap_set(swap_bitmap, swap_idx, true);
}
