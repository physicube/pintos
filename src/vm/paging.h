#ifndef PAGING_H
#define PAGING_H
#include <hash.h>
#include "vm/frame.h"
#include "threads/thread.h"
enum supte_status
{
    FRAME,
    SWAP,
    ZERO,
    FILE
};

struct SUPT
{
    struct hash page;
};

struct SUPTE
{
    void * uaddr;
    void * paddr;
    enum supte_status status;
    bool dirty_bit;
    size_t swap_idx;
    struct file * f;
    size_t offset, read_b, zero_b;
    bool is_write;
    
    struct hash_elem elem;
};

void supt_init(void);
void supt_remove(void);
bool frame_install(struct SUPT * supt, void * uaddr, void * paddr, bool mode);
bool frame_install_filesys(struct SUPT* supt, struct file * file, void * uaddr, size_t off, size_t read_b, size_t zero_b, bool write);
bool page_load(struct SUPT * supt, uint32_t *pagedir, void * uaddr);
void make_page_victim(struct SUPT * supt, void * addr, bool mode);
struct SUPTE * find_supte_in_supt(struct SUPT * supt, void *uaddr);
void set_dirty_supt(struct SUPT * supt, void * uaddr, bool dirty_bit);
void get_and_set_swap_idx(struct SUPT * supt, void *uaddr);

unsigned hash_func1(const struct hash_elem *elem, void *aux);
bool hash_func2(const struct hash_elem *a, const struct hash_elem *b, void *aux);
#endif