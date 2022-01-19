#include <hash.h>
#include <list.h>
#include <stdio.h>
#include "lib/kernel/hash.h"
#include "lib/kernel/list.h"
#include "vm/frame.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"

static struct list_elem *victim_ptr; 

static unsigned frame_hash_func(const struct hash_elem *elem, void *aux);
static bool     frame_less_func(const struct hash_elem *, const struct hash_elem *, void *aux);

static struct frame_table_entry* pick_frame_to_evict(uint32_t* pagedir);
struct frame_table_entry* clock_next_frame(void);

void
vm_frame_init ()
{
  lock_init (&frame_lock);
  hash_init (&frame_map, frame_hash_func, frame_less_func, NULL);
  list_init (&frame_list);
  victim_ptr = NULL;
}

static unsigned frame_hash_func(const struct hash_elem *elem, void *aux UNUSED)
{
  struct frame_table_entry *entry = hash_entry(elem, struct frame_table_entry, helem);
  return hash_bytes( &entry->kpage, sizeof entry->kpage );
}
static bool frame_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  struct frame_table_entry *a_entry = hash_entry(a, struct frame_table_entry, helem);
  struct frame_table_entry *b_entry = hash_entry(b, struct frame_table_entry, helem);
  return a_entry->kpage < b_entry->kpage;
}

/* Allocate a new frame */
void*
vm_frame_allocate (enum palloc_flags flags, void *upage)
{
  lock_acquire (&frame_lock);

  void *frame_page = palloc_get_page (PAL_USER | flags);
  if (frame_page == NULL) {

    struct frame_table_entry *evicted = pick_frame_to_evict( thread_current()->pagedir );
    ASSERT (evicted != NULL && evicted->t != NULL);
    ASSERT (evicted->t->pagedir != (void*)0xcccccccc);

    pagedir_clear_page(evicted->t->pagedir, evicted->upage);

    bool is_dirty = false;
    is_dirty = is_dirty || pagedir_is_dirty(evicted->t->pagedir, evicted->upage)
      || pagedir_is_dirty(evicted->t->pagedir, evicted->kpage);

    swap_index_t swap_idx = vm_swap_out( evicted->kpage );
    
	vm_supt_set_swap(evicted->t->supt, evicted->upage, swap_idx);
    vm_supt_set_dirty(evicted->t->supt, evicted->upage, is_dirty);
    
	vm_frame_do_free(evicted->kpage,true);

    frame_page = palloc_get_page (PAL_USER | flags);
    ASSERT (frame_page != NULL); 
  }

  struct frame_table_entry *frame = malloc(sizeof(struct frame_table_entry));
  if(frame == NULL) {
    lock_release (&frame_lock);
    return NULL;
  }

  frame->t = thread_current ();
  frame->upage = upage;
  frame->kpage = frame_page; 

  hash_insert (&frame_map, &frame->helem);
  list_push_back (&frame_list, &frame->lelem);

  lock_release (&frame_lock);
  return frame_page;
}


void
vm_frame_free (void *kpage)
{
  lock_acquire (&frame_lock);
  vm_frame_do_free (kpage, true);
  lock_release (&frame_lock);
}


void vm_frame_remove_entry (void *kpage)
{
  lock_acquire (&frame_lock);
  vm_frame_do_free (kpage, false);
  lock_release (&frame_lock);
}

void
vm_frame_do_free (void *kpage, bool free_page)
{
  ASSERT (lock_held_by_current_thread(&frame_lock) == true);
  ASSERT (is_kernel_vaddr(kpage));
  ASSERT (pg_ofs (kpage) == 0); // should be aligned

  // hash lookup : a temporary entry
  struct frame_table_entry f_tmp;
  f_tmp.kpage = kpage;

  struct hash_elem *h = hash_find (&frame_map, &(f_tmp.helem));
  if (h == NULL) {
    PANIC ("The page to be freed is not stored in the table");
  }

  struct frame_table_entry *f;
  f = hash_entry(h, struct frame_table_entry, helem);

  hash_delete (&frame_map, &f->helem);
  list_remove (&f->lelem);
  
  free(f);

  if(free_page) palloc_free_page(kpage);  
}

struct frame_table_entry* pick_frame_to_evict( uint32_t *pagedir ) {
  size_t n = hash_size(&frame_map);
  if(n == 0) 
    PANIC("Frame table is empty.");

  size_t it;
  for(it = 0; it <= n + n; ++ it) 
  {
    struct frame_table_entry *e = clock_next_frame();

    // if referenced, give a second chance.
    if( pagedir_is_accessed(pagedir, e->upage)) {
      pagedir_set_accessed(pagedir, e->upage, false);
      continue;
    }

    // victim
    return e;
  }

  PANIC ("Can't evict any frame. \n");
}

struct frame_table_entry* clock_next_frame(void)
{
  if (list_empty(&frame_list))
    PANIC("Frame table is empty, can't happen - there is a leak somewhere");

  struct frame_table_entry *e;
  if(victim_ptr!=NULL){
	  e = list_entry(victim_ptr,struct frame_table_entry,lelem);
  }
  else{
	  victim_ptr = list_begin(&frame_list);
	  e = list_entry(victim_ptr,struct frame_table_entry,lelem);
  }
  victim_ptr = list_next(victim_ptr);
  if(victim_ptr == list_end(&frame_list)){
	  victim_ptr = list_begin(&frame_list);
  }

  ASSERT(e->upage < (void*)0xc0000000);
	
  return e;
}

