#include "vm/page.h"
#include <stdio.h>
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"

// user addr에서 기본적으로 fream은 1개 이지만 eviction이 있으면 여러개될수도.
// swap table에는 pid나 pointer 등으로 원래 정보를 찾아줄 필요가 있다.
// supplemental page table은 process당 1개
struct sup_pte
{
    struct fte *fte;
    uint32_t page_no;

    bool accessed;
    bool dirty;
};

struct fte* sup_pte_get_fte(struct sup_pte *spte)
{
    uint32_t *pd = thread_current()->pagedir;
}

/* uaddr을 보고 
*/
bool sup-_page(void *uaddr, bool writable)
{
    ASSERT(is_user_vaddr(uaddr));
    uint32_t *pd = thread_current()->pagedir;


}
