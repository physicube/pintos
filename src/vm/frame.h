#ifndef FRAME_H
#define FRAME_H

#include <hash.h>
#include "lib/kernel/hash.h"

#include "threads/synch.h"
#include "threads/palloc.h"

struct hash frame_map;

struct fte//frame_table_entry
{
  void *paddr;              
  void *vaddr;              
 
  struct thread *t;         
  bool is_evict;      

  struct hash_elem hash_elem;   
  struct list_elem list_elem;   //for ease of clock algorithm.        
};

static struct lock frame_lock;
static struct list frame_list_eviction;      
static struct list_elem *evict_p = NULL; 
static struct hash_elem * hash_tmp;

static struct fte* choose_evict(uint32_t* pagedir);
//static void get_and_set_swap_idx(struct SPTABLE * supt, void *vaddr);

/* Functions for Frame manipulation. */

void frame_init ();
void* frame_allocate (enum palloc_flags flags, void *vaddr);

void frame_free_external (void * paddr, bool mode); // 1 for delete resources, 0 for delete list only.
void frame_free_internal (void *paddr, bool delete_flag);
void frame_set_is_evict(void *paddr, bool new_value);
void calculate_and_set_dirty_bit(bool dirty_bit, struct fte * fte);

static unsigned frame_hash_func(const struct hash_elem *elem, void *aux);
static bool     frame_less_func(const struct hash_elem *, const struct hash_elem *, void *aux);


#endif /* vm/frame.h */
