#include <list.h>
#include <stdio.h>
#include <hash.h>
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "lib/kernel/hash.h"
#include "lib/kernel/list.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/synch.h"
#include "vm/frame.h"
#include "vm/paging.h"

struct list frame_list;
struct lock frame_lock;
struct list_elem * clock_ptr;

static struct FTE * select_to_be_evicted_frame(unsigned int * pagedir);
static struct FTE * get_frame_in_list(struct list * list, void * addr, bool mode);
static void calculate_and_set_dirty_bit(bool dirty_bit, struct FTE * fte);
void * frame_free_prelock_aquire(void *addr, bool mode);

void 
frame_init(void)
{
    clock_ptr = NULL;
    list_init(&frame_list);
    lock_init(&frame_lock);
}

void *
frame_allocate(enum palloc_flags flag, void *addr)
{
    struct thread * t = thread_current();
    void * frame_mold = NULL;
    struct FTE * fte = NULL;

    lock_acquire(&frame_lock);
    if(!(frame_mold = palloc_get_page(PAL_USER | flag))) // if frame_mold is NULL
    { 
        // failed.
        fte = select_to_be_evicted_frame(t->pagedir);
        pagedir_clear_page(fte->master->pagedir, fte->uaddr);
        calculate_and_set_dirty_bit(false, fte);
        get_and_set_swap_idx(fte->master->supt, addr);
        frame_free_prelock_aquire(fte->paddr, true);
        if(!(frame_mold = palloc_get_page(PAL_USER | flag)))
        {
            PANIC("I cannot do anything more than this in frame_allocate.");
        }
        fte = NULL;
    }

    if(!(fte = (struct FTE * )malloc(sizeof(struct FTE))))
    {
        lock_release(&frame_lock);
        return NULL;
    }
    else
    {
        fte->master = t;
        fte->uaddr = addr;
        fte->paddr = frame_mold;
        fte->eviction = true;
        list_push_back(&frame_list, &fte->elem);
           
        struct FTE * fte_;
        int it=0;
        for(struct list_elem *tmp = list_front(&frame_list); tmp != list_tail(&frame_list); tmp = list_next(tmp))
        {
          fte_ = list_entry(tmp, struct FTE, elem);
          printf("frame %d : kpage : %p, upage: %p,  owner : %s \n",it++,fte_->paddr, fte_->uaddr, fte_->master->name);

        }
        printf("\n\n");
        
        lock_release(&frame_lock);
        return fte->paddr;
    }
    printf("you cannot come here in frame_allocate. :P\n");
    NOT_REACHED();
}

void * // guaranteed that lock is already acuired.
frame_free_prelock_aquire(void *addr, bool mode)
{
    struct FTE * fte = get_frame_in_list(&frame_list, addr, false); 
    list_remove(&fte->elem);
    if(mode)
    {
        palloc_free_page(addr);
    }
    free(fte);
}

void 
frame_free_mode(void *addr, bool mode)
{
    lock_acquire(&frame_lock);
    frame_free_prelock_aquire(addr, mode);
    lock_release(&frame_lock);
}

void
make_victim_frame(void * frame, bool mode) // mode == true -> make frame evict
{
    struct FTE * fte = NULL;
    lock_acquire(&frame_lock);
    fte = get_frame_in_list(&frame_list, frame, false);
    fte->eviction = mode;
    lock_release(&frame_lock);
}

struct FTE * 
get_frame_in_list(struct list * list, void * addr, bool mode)
{
    struct FTE * fte = NULL;

    if(!list_empty(list))
    {
        for(struct list_elem *tmp = list_front(list); tmp != list_tail(list); tmp = list_next(tmp))
        {
            fte = list_entry(tmp, struct FTE, elem);
            if(mode)
            {
                if((size_t)fte->uaddr == (size_t)addr)
                return fte;
            }
            else
            {
                if((size_t)fte->paddr == (size_t)addr)
                return fte;
            }
        }
    }
    else
    {
        PANIC("FRAME LIST IS EMPTY????\n");
    }
    printf("You cannot come here in get_frame_in_list. :P\n");
    NOT_REACHED();
}


struct FTE * 
select_to_be_evicted_frame(unsigned int * pagedir)
{
    //implement clock algorithm.

    size_t num = list_size(&frame_list);
    size_t i;
    struct FTE * tmp = NULL;
   
    for(i = 0; i < 2*num; i++)
    {
        if(clock_ptr == NULL || clock_ptr == list_end(&frame_list))
        {
            clock_ptr = list_begin(&frame_list);
        }
        else
        {
            clock_ptr = list_next(clock_ptr);
        }
        tmp = list_entry(clock_ptr, struct FTE, elem);

        if(tmp->eviction)
        {
            continue;
        }
        else if(pagedir_is_accessed(pagedir, tmp->uaddr))
        {
            pagedir_set_accessed(pagedir, tmp->uaddr, false);
            continue;
        }
        return tmp;
    }
    printf("You cannot come here! maybe something was wrong. :p\n");
    NOT_REACHED();
}

void 
calculate_and_set_dirty_bit(bool dirty_bit, struct FTE * fte)
{
    dirty_bit = dirty_bit || pagedir_is_dirty(fte->master->pagedir, fte->uaddr);
    dirty_bit = dirty_bit || pagedir_is_dirty(fte->master->pagedir, fte->paddr);
    set_dirty_supt(fte->master->supt, fte->uaddr, dirty_bit);
}