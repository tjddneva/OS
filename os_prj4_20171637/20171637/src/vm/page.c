#include <hash.h>
#include <string.h>
#include "lib/kernel/hash.h"
#include "page.h"
#include "frame.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

static unsigned supte_hash_func(const struct hash_elem *elem, void *aux);
static bool supte_less_func(const struct hash_elem *, const struct hash_elem *, void *aux);
static void supte_destroy_func(struct hash_elem *elem, void *aux);


static unsigned supte_hash_func(const struct hash_elem *elem, void *aux UNUSED){
    struct supplemental_page_table_entry *entry = hash_entry(elem, struct supplemental_page_table_entry, elem);
    return hash_int((int)entry->upage);
}
static bool supte_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED){
    struct supplemental_page_table_entry *e1 = hash_entry(a, struct supplemental_page_table_entry, elem);
    struct supplemental_page_table_entry *e2 = hash_entry(b, struct supplemental_page_table_entry, elem);
    return e1 -> upage < e2 -> upage;
}
static void supte_destroy_func(struct hash_elem *elem, void *aux UNUSED){
    struct supplemental_page_table_entry *entry = hash_entry(elem, struct supplemental_page_table_entry, elem);

    //Clean up the associated frame.
    if(entry->kpage != NULL){
        ASSERT(entry -> status == ON_FRAME);
        vm_frame_remove_entry(entry->kpage);
    }

    else if(entry -> status == ON_SWAP){
        vm_swap_free(entry->swap_index);
    }
    //Finally remove the entry.
    free(entry);
}

struct supplemental_page_table *vm_supt_create(void){
    struct supplemental_page_table *supt = 
    (struct supplemental_page_table *) malloc(sizeof(struct supplemental_page_table));

    hash_init(&supt->page_map, supte_hash_func, supte_less_func, NULL);
    return supt;
}

void vm_supt_destroy(struct supplemental_page_table *supt){
    ASSERT(supt != NULL);
    hash_destroy(&supt->page_map, supte_destroy_func);
    free(supt);
}

struct supplemental_page_table_entry *vm_supt_look_up (struct supplemental_page_table *supt, void *page){
    struct supplemental_page_table_entry supte_tmp;
    supte_tmp.upage = page;
    struct hash_elem *elem = hash_find(&supt->page_map, &supte_tmp.elem);
    if(elem == NULL)
        return NULL;
    else 
        return hash_entry(elem,struct supplemental_page_table_entry,elem);
}
bool vm_supt_has_entry(struct supplemental_page_table *supt, void *page){
    struct supplemental_page_table_entry *supte = vm_supt_look_up(supt, page);
    if(supte == NULL)
        return false;
    else
        return true;
}

bool vm_supt_install_frame(struct supplemental_page_table *supt, void *upage, void *kpage){
    struct supplemental_page_table_entry *supte;
    supte = (struct supplemental_page_table_entry *) malloc(sizeof(struct supplemental_page_table_entry));

    supte -> upage = upage;
    supte -> kpage = kpage;
    supte -> status = ON_FRAME;
    supte -> dirty = false;
    supte -> swap_index = -1;

    struct hash_elem *prev = hash_insert(&supt->page_map, &supte->elem);
    if(prev == NULL){
		/* success */
        return true;
    }
    else {
		/* fail */
        free(supte);
        return false;
    }
}

bool vm_supt_install_filesys(struct supplemental_page_table *supt, void *upage,
    struct file *file, off_t offset, uint32_t read_bytes, uint32_t zero_bytes,bool writable){
        struct supplemental_page_table_entry *supte;
        supte = (struct supplemental_page_table_entry *)malloc(sizeof(struct supplemental_page_table_entry));
        supte -> upage = upage;
        supte -> kpage = NULL;
        supte -> status = FROM_FILESYS;
        supte -> dirty = false;
        supte -> file = file;
        supte -> file_offset = offset;
        supte -> read_bytes = read_bytes;
        supte -> zero_bytes = zero_bytes;
        supte -> writable = writable;

        struct hash_elem *prev = hash_insert(&supt->page_map, &supte->elem);
        if(prev == NULL) return true;
        else {
            PANIC("There's already entry.");
            return false;
        }

    }

bool vm_supt_set_swap(struct supplemental_page_table *supt, void *page, swap_index_t swap_index){
    struct supplemental_page_table_entry *supte;
    supte = vm_supt_look_up(supt,page);
    if(supte == NULL)
        return false;
    supte -> status = ON_SWAP;
    supte -> kpage = NULL;
    supte -> swap_index = swap_index;
    return true;
}

bool vm_supt_set_dirty(struct supplemental_page_table *supt, void *page, bool value){
    struct supplemental_page_table_entry *supte = vm_supt_look_up(supt,page);
    if(supte == NULL)
        PANIC("No exist.");
    else {
        supte -> dirty = supte->dirty || value;
        return true;
    }
}
bool vm_supt_mm_unmap(struct supplemental_page_table *supt, uint32_t *pagedir, void *page, 
      struct file *file, off_t offset, size_t bytes){
    struct supplemental_page_table_entry *supte = vm_supt_look_up(supt, page);
    if(supte == NULL)
        PANIC("Some pages are missing");

    bool is_dirty;
    switch(supte->status){
        case ON_FRAME:
            ASSERT (supte->kpage != NULL);
            //If upage or mapped frame is dirty, write that to file.
            is_dirty = supte->dirty;
            is_dirty = is_dirty || pagedir_is_dirty(pagedir, supte->upage)||
                pagedir_is_dirty(pagedir, supte->kpage);
            if(is_dirty){
                file_write_at(file, supte->upage, bytes, offset);
            }

            //clear the page mapping and free it.
            vm_frame_free(supte->kpage);
            pagedir_clear_page(pagedir, supte->upage);
            break;

        case ON_SWAP:
            is_dirty = supte->dirty;
            is_dirty = is_dirty || pagedir_is_dirty(pagedir,supte->upage);
            //If it's dirty, then load from the swap and write that to the file.
            if(is_dirty){
                void *tmp_page = palloc_get_page(0);
                vm_swap_in(supte->swap_index, tmp_page);
                file_write_at(file,tmp_page,PGSIZE,offset);
                palloc_free_page(tmp_page);
            }
            else {
                vm_swap_free(supte->swap_index);
            }
            break;
        case FROM_FILESYS:
            break;

        default : 
            PANIC("NO WAY.");
    }

    hash_delete(&supt->page_map, &supte->elem);
    return true;
}    


