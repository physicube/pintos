#include <hash.h>
#include <string.h>
#include <stdio.h>
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

#include "threads/synch.h"
#include "vm/paging.h"
#include "vm/swapping.h"
#include "vm/frame.h"
#include "filesys/file.h"
#include "lib/kernel/hash.h"

void supt_init(void)
{
    struct thread * t = thread_current();
    t->supt = (struct SUPT *)malloc(sizeof(struct SUPT));
    list_init(&t->supt->page_list);
}

void supt_remove(void)
{
    struct SUPTE * supte;
    struct thread * t = thread_current();
    for(;!list_empty(&t->supt->page_list);)
    {
        struct list_elem *elem = list_pop_front (&t->supt->page_list) ;
        supte = list_entry(elem, struct SUPTE, lelem);
        free(supte);
    }
}

bool frame_install(struct SUPT * supt, void * uaddr, void * paddr, bool mode) // mode true = frame, false = zero page
{
    //install a frame which is in supt.
    struct SUPTE * supte = (struct SUPTE *)malloc(sizeof(struct SUPTE));
    supte->dirty_bit = false;
    supte->uaddr = uaddr;
    if(mode)
    {
        supte->status = FRAME;
        supte->swap_idx = -1;
        supte->paddr = paddr;
    }
    else // install zero page
    {
        supte->status = ZERO;
        supte->dirty_bit = false;
        supte->paddr = NULL;        
    }

    list_push_back(&supt->page_list, &supte->lelem);
    struct SUPTE * supte_;
    int it = 0;
    for(struct list_elem *tmp = list_front(&supt->page_list); tmp != list_tail(&supt->page_list); tmp = list_next(tmp))
    {
      supte_ = list_entry(tmp, struct SUPTE, lelem);
      printf("hash %d : kpage : %p, upage: %p,  status : %d, owner : %s \n",it++,supte_->paddr, supte_->uaddr, supte_->status, thread_current()->name);
    }
    printf("\n\n");
    return true;
}

bool frame_install_filesys(struct SUPT* supt, struct file * file, void * uaddr, size_t off, size_t read_b, size_t zero_b, bool write)
{
    struct SUPTE * supte = (struct SUPTE *)malloc(sizeof(struct SUPTE));
    supte->f = file;
    supte->uaddr = uaddr;
    supte->paddr = NULL;
    supte->offset = off;
    supte->read_b = read_b;
    supte->zero_b = zero_b;
    supte->is_write = write;
    supte->dirty_bit = false;
    supte->status = FILE;
    printf("Input upage : %p\n",uaddr);
    
    list_push_back(&supt->page_list, &supte->lelem);
    struct SUPTE * supte_;
    int it=0;
    for(struct list_elem *tmp = list_front(&supt->page_list); tmp != list_tail(&supt->page_list); tmp = list_next(tmp))
    {
      supte_ = list_entry(tmp, struct SUPTE, lelem);
      printf("hash %d : kpage : %p, upage: %p,  status : %d, owner : %s \n",it++,supte_->paddr, supte_->uaddr, supte_->status, thread_current()->name);
    }
    printf("\n\n");
    return true;
}

bool page_load(struct SUPT * supt, uint32_t *pagedir, void * uaddr)
{
    bool write = true;
    struct SUPTE * supte = find_supte_in_supt(supt, uaddr);
    void * frame_mold = NULL;
    enum supte_status status;
    if(!supte) return false;
    if(supte->status == FRAME) return true;

    if(!(frame_mold = frame_allocate(PAL_USER, uaddr))) return false;
    status = supte->status;

    if(status == ZERO)
    {
        memset(frame_mold, 0, 1 << 12);
    }
    else if(status == SWAP)
    {
        swap_in(supte->swap_idx, frame_mold);
    }
    else if(status == FILE)
    {
        size_t read_num = -1;
        file_seek (supte->f, supte->offset);
        if((read_num = file_read (supte->f, supte->paddr, supte->read_b)) != supte->read_b)
        {
            frame_free_mode(frame_mold, true);
            return false;
        }
        memset (frame_mold + read_num, 0, supte->zero_b);
    }
    else if(status != FRAME)
    {
        PANIC("HOW COME TO THIS AREA? in load_page\n");
    }

    if(!pagedir_set_page(pagedir, uaddr, frame_mold, write))
    {
        frame_free_mode(frame_mold,true);
        return false;
    }
    supte->paddr = frame_mold;
    supte->status = FRAME;
    pagedir_set_dirty(pagedir, frame_mold, false);
    make_victim_frame(frame_mold, false);
    return true;
}

void 
make_page_victim(struct SUPT * supt, void * addr, bool mode) // mode true == make page victim
{
    struct SUPTE * supte = find_supte_in_supt(supt, addr);
    if(mode)
    {
        if(!supte)
        {
            make_victim_frame(supte->paddr, true);
        }
        else
            return;
    }
    else
    {
        if(supte->status == FRAME)
            make_victim_frame(supte->paddr, false);
    }

}


struct SUPTE * find_supte_in_supt(struct SUPT * supt, void *uaddr)
{
    struct SUPTE * supte;
    if(!list_empty(&supt->page_list))
    {
        for(struct list_elem *tmp = list_front(&supt->page_list); tmp != list_tail(&supt->page_list); tmp = list_next(tmp))
        {
            supte = list_entry(tmp, struct SUPTE, lelem);
            if((size_t)supte->uaddr == (size_t)uaddr)
                return supte;
        }
        return NULL; // cannot find supte.
    }
    else
    {
        PANIC("List is empty!\n");
        return NULL;
    }
}

void set_dirty_supt(struct SUPT* supt, void * uaddr, bool dirty_bit)
{
    struct SUPTE * supte = find_supte_in_supt(supt, uaddr);
    if(!supte)
    {
        printf("something was wrong in set_dirty_supt. :p\n");
        NOT_REACHED();
    }
    else
    {
        supte->dirty_bit = supte->dirty_bit || dirty_bit;
    }
}

void get_and_set_swap_idx(struct SUPT * supt, void *uaddr)
{
    struct SUPTE * supte = find_supte_in_supt(supt, uaddr);
    if(!supte)
    {
        printf("something was wrong in get_and_set_swap_idx. :p\n");
        NOT_REACHED();
    }
    else
    {
        supte->status = SWAP;
        supte->paddr = NULL;
        supte->swap_idx = swap_out(uaddr);
    }
}