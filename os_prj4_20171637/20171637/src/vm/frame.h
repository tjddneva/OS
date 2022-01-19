#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <hash.h>
#include <list.h>
#include "lib/kernel/hash.h"
#include "threads/synch.h"
#include "threads/palloc.h"


struct lock frame_lock;

struct hash frame_map;
struct list frame_list;      

/* Frame Table Entry */
struct frame_table_entry
  {
    void *kpage;               /* Kernel page, mapped to physical address */

    void *upage;               /* User (Virtual Memory) Address, pointer to page */
    struct thread *t;          /* The associated thread. */

    struct hash_elem helem;    /* frame_map */
    struct list_elem lelem;    /* frame_list */
  };

/* Initialize */
void vm_frame_init(void);

/* Create a frame page corresponding to user virtual address upage. 
After the page mapping, return the kernel address of created page frame. */
void* vm_frame_allocate(enum palloc_flags flag, void *upage);

void vm_frame_free(void *);
void vm_frame_remove_entry(void *);
void vm_frame_do_free (void *, bool);

#endif
