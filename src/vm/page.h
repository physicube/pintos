#ifndef PAGE_H
#define PAGE_H
#include "filesys/off_t.h"
#include "vm/swap.h"
#include "vm/frame.h"
#include <hash.h>

#define ZERO 0       
#define SPTE_FRAME 1        
#define ON_SWAP 2         
#define LOAD_FILESYS 3     

struct SPTABLE
  {
    struct hash page_table;
  };

struct SPTE
  {
    void *vaddr;              
    void *paddr;                                                                          
    struct hash_elem hash_elem;
    uint32_t status;
    bool dirty;              
    // for ON_SWAP
    swap_index_t swap_idx;                                   
    // for FROM_FILESYS
    struct file *file;
    size_t ofs;
    uint32_t read_b, zero_b;
    bool writable;
  };


static bool load_page_from_FILESYS(struct SPTE *, void *);

struct SPTABLE* suptable_create (void);
void free_page (struct SPTABLE *supt);
bool install_frame (struct SPTABLE *supt, void *vaddr, void *kpage, bool mode); // true == insall frmae, false = install frame with zero page
bool install_frame_by_file (struct SPTABLE *supt, struct file * file, void *vaddr,
     size_t ofs, uint32_t read_b, uint32_t zero_b, bool writable);
bool set_page_dirty (struct SPTABLE *supt, void *page, bool value);
bool set_page_swap (struct SPTABLE *supt, void *page, unsigned swap_idx);
bool load_page(struct SPTABLE *supt, uint32_t *pagedir, void *vaddr);

bool
syscall_munmap_help(struct SPTABLE *supt, uint32_t *pagedir, void *page, struct file *file, size_t ofs, size_t bytes);

void make_frame_unvictim(struct SPTABLE *supt, void *page);
void make_frame_victim(struct SPTABLE *supt, void *page);

struct SPTE* find_page_by_vaddr (struct SPTABLE *supt, void *page);


static unsigned hash_func(const struct hash_elem *elem, void *aux);
static bool     less_func(const struct hash_elem *, const struct hash_elem *, void *aux);
static void     free_func(struct hash_elem *elem, void *aux);



#endif
