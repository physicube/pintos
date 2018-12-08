#ifndef SWAPPING_H
#define SWAPPING_H

void swap_init(void);
size_t swap_out(void * addr);
void swap_in(size_t idx, void *addr);
void swap_free(size_t idx);
#endif