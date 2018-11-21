#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <debug.h>
#include <stdint.h>
#include <stdbool.h>

#define BITMASK(SHIFT, CNT) (((1ul << (CNT)) - 1) << (SHIFT))

/* frame offset (bits 0:12). */
#define FRSHIFT 0                          
#define FRBITS  12                         
#define FRSIZE  (1 << PGBITS)              
#define FRMASK  BITMASK(PGSHIFT, PGBITS)  



#endif