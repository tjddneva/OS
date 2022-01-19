#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"

#ifdef VM
#include "vm/page.h"
#include "vm/frame.h"

bool expand_stack(struct supplemental_page_table*, void*);
bool handle_mm_fault(struct supplemental_page_table*, uint32_t*, void*);
void preload(const void *, size_t);

typedef int mmapid_t;

struct mmap_desc {
  mmapid_t id;
  struct list_elem elem;
  struct file* file;

  void *addr;   // where it is mapped to? store the user virtual address
  size_t size;  // file size
};
#endif

struct file_desc {
  int id;
  struct list_elem elem;
  struct file* file;
  struct dir* dir;        /* In case of directory opening, dir != NULL */
};


tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);


#endif /* userprog/process.h */
