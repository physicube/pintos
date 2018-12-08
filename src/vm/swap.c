#include <bitmap.h>
#include "devices/block.h"
#include "threads/vaddr.h"
#include <stdio.h>

#include "vm/swapping.h"

static struct block *swap_blk;
static struct bitmap *swap_bit;
size_t sector_per_page = 0;

void 
swap_init(void)
{
    if(sector_per_page == 0)
    {
        sector_per_page = PGSIZE / BLOCK_SECTOR_SIZE;
    }
    if(!(swap_blk = block_get_role(BLOCK_SWAP)))
    {
        printf("GET BLOCK is failed in swap_init. :P\n");
        NOT_REACHED();
    }
    else
    {
        bitmap_set_all((swap_bit = bitmap_create(block_size(swap_blk) / sector_per_page)), true);
    }
}

void 
swap_in(size_t idx, void *addr)
{
    size_t it;
    for(it = 0; it < sector_per_page; it++)
    {
        block_read(swap_blk, idx *sector_per_page + it, addr + (BLOCK_SECTOR_SIZE * it));
    }
    bitmap_set(swap_bit, idx, true);
}

size_t 
swap_out(void * addr)
{
    size_t idx = bitmap_scan(swap_bit, 0, 1, true), i;
    for(i = 0; i < sector_per_page; i++)
    {
        block_write(swap_blk, idx * sector_per_page + i, addr + (BLOCK_SECTOR_SIZE * i));
    }
    bitmap_set(swap_bit, idx, false);
    return idx;
}

void 
swap_free(size_t idx)
{
    bitmap_set(swap_bit, idx, true);
}
