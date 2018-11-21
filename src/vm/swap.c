#include "devices/block.h"
#include "vm/swap.h"
#include <stdio.h>

static struct block *swap;

void swap_initialize(void)
{
    swap = block_get_role(BLOCK_SWAP);
    printf("block_type %d\n", block_type(swap));
}
