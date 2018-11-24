#include "vm/frame.h"
#include <stdio.h>
#include "userprog/pagedir.h"
#include "threads/palloc.h"



/* address에서 supplement page table을 보고, frame을 찾는다
만약 supplement page table에 page가 없으면 -> 
page에 맞는 frame이 할당이 안되어 있으면, frame을 할당한다. 이때 frame이
이미 사용중이거나 공간이 없으면 eviction을 할 것 같다.

*/