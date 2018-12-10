#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "devices/block.h"
#include "threads/synch.h"
#include <stdio.h>

struct swaptable
{
  struct lock lock; 
  struct bitmap *used_map;
};


void swap_init();
block_sector_t alloc_swap();
void free_swap(block_sector_t sector);
void swap_write_page(char *addr, block_sector_t sector);
void swap_read_page(char *addr, block_sector_t sector);

#endif