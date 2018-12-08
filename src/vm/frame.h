#ifndef FRAME_H
#define FRAME_H
#include <hash.h>
#include <list.h>
#include "threads/thread.h"
#include "threads/palloc.h"

struct FTE // frame table entry
{
    void *paddr;
    void *uaddr;
    struct thread * master;
    bool eviction;
    struct list_elem elem;
};

void 
frame_init(void);

void *
frame_allocate(enum palloc_flags flag, void *addr);

void 
frame_free_mode(void *addr, bool mode);

void
make_victim_frame(void * frame, bool mode);

#endif