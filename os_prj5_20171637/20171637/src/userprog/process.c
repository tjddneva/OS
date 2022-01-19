#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/frame.h"
#include "vm/page.h"

#ifndef VM
#define vm_frame_allocate(x, y) palloc_get_page(x)
#define vm_frame_free(x) palloc_free_page(x)
#endif

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   `cmdline`. The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy = NULL;
  tid_t tid;

  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  char copy_name[256];
  strlcpy(copy_name,file_name,strlen(file_name)+1);
  char *save_ptr;
  char* cmd_name;
  cmd_name = strtok_r(copy_name," ",&save_ptr);
  if(filesys_open(cmd_name)==NULL){
	return -1;
  }

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (cmd_name, PRI_DEFAULT, start_process, fn_copy);
  sema_down(&(thread_current()->mylord));  
  if (tid == TID_ERROR)
    palloc_free_page(fn_copy);

  struct list_elem* e;
  struct thread* tmp;
  struct thread* cur = thread_current();

  e = list_begin(&(cur->child));
  while(e!=list_end(&(cur->child))){
	tmp = list_entry(e, struct thread, child_elem);

	if(tmp->zomboid == true){
		return process_wait(tid);
	}
	e = list_next(e);
  }

  return tid;  
}


/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;	
  struct intr_frame if_;
  bool success = false;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  /* If load failed, quit. */
  palloc_free_page (file_name);

  sema_up(&thread_current()->parent->mylord);
  if (!success){
	thread_current()->zomboid = true;
	thread_current()->exit_status = -1;
    thread_exit ();
  } 

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.
   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid)
{
  struct list_elem* e;
  struct thread* tmp = NULL;
  struct thread* cur = thread_current();
  int exit_status = -1;

  e = list_begin(&(cur->child));
  while (e != list_end(&(cur->child))){
    tmp = list_entry(e, struct thread, child_elem);
    
	if (child_tid != tmp->tid){
		e = list_next(e);
		continue;
	}

	sema_down(&(tmp->child_lock));
	exit_status = tmp->exit_status;
	list_remove(&(tmp->child_elem));
	sema_up(&(tmp->remember));
	
	return exit_status;
  }
  return -1;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  struct list *fdlist = &cur->file_descriptors;
  while (!list_empty(fdlist)) {
    struct list_elem *e = list_pop_front (fdlist);
    struct file_desc *desc = list_entry(e, struct file_desc, elem);
    file_close(desc->file);
    palloc_free_page(desc); 
  }

#ifdef VM
  // mmap descriptors  
  struct list *mmlist = &cur->mmap_list;
  while (!list_empty(mmlist)) {
    struct list_elem *e = list_begin (mmlist);
    struct mmap_desc *desc = list_entry(e, struct mmap_desc, elem);

	sys_munmap(desc->id);
    // in sys_munmap(), the element is removed from the list
  }
#endif

#ifdef VM
  // Destroy the SUPT, its all SPTEs, all the frames, and swaps.
  // Important: All the frames held by this thread should ALSO be freed
  // (see the destructor of SPTE). Otherwise an access to frame with
  // its owner thread had been died will result in fault.
  vm_supt_destroy (cur->supt);
  cur->supt = NULL;
#endif

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
 /* 
  for(int i=3; i<131; i++){
    if(cur->fd[i]!=NULL){
	  sys_close(i);
	}
  }*/
  if(cur->executing_file) {
    file_allow_write(cur->executing_file);
    file_close(cur->executing_file);
  }

  sema_up(&(cur->child_lock));
  sema_down(&(cur->remember));
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory, as well as SPTE. */
  t->pagedir = pagedir_create ();
#ifdef VM
  t->supt = vm_supt_create ();
#endif

  if (t->pagedir == NULL)
    goto done;
  process_activate ();

  char copy_name[256];
  strlcpy(copy_name,file_name,strlen(file_name)+1);
  char *save_ptr;
  char *cmd_name;
  cmd_name = strtok_r(copy_name," ",&save_ptr);

  /* Open executable file. */
  file = filesys_open (cmd_name);
  if (file == NULL)
    {
      printf ("load: %s: open failed\n", file_name);
      goto done;
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done;
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type)
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file))
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  char copy_name2[256];
  char *save_ptr2;
  int argc=0;
  int len=0;
  uint8_t word_align;
  char* argu;
  char **mystack = (char**)malloc(sizeof(char*)*256);
  char **mystack_address = (char**)malloc(sizeof(char*)*256);
  strlcpy(copy_name2,file_name,strlen(file_name)+1);

  argu = strtok_r(copy_name2," ",&save_ptr2);
  while(argu!=NULL){
	mystack[argc] = argu;
	argu = strtok_r(NULL," ",&save_ptr2);
	argc++;
  }

  for(int i=argc-1; i>=0; i--){
	*esp =*esp-strlen(mystack[i])-1;
	len = len + strlen(mystack[i])+1;
	strlcpy(*esp,mystack[i],strlen(mystack[i])+1);
	mystack_address[i] = *esp;
  }

  if(len%4==0){
	word_align = 0;
  }
  else{
	  word_align = 4 - (len % 4);
  }
  *esp = *esp - word_align;

  *esp = *esp - 4;
  **(char**)esp = 0;

  for(int i=argc-1; i>=0; i--){
	*esp= *esp - 4;
	//**(uint32_t**)esp = mystack_address[i];
	*((void**) *esp) = mystack_address[i];
  }

  *esp = *esp - 4;
  //**(uint32_t**)esp = *esp+4;
  *((void**) *esp) = (*esp + 4);

  *esp = *esp - sizeof(int);
  **(int**)esp = argc;

  *esp = *esp-4;
  **(uint32_t**)esp = 0;
  
  free(mystack);
  free(mystack_address);
  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;
  
  file_deny_write(file);
  thread_current()->executing_file = file;
 done:
  /* We arrive here whether the load is successful or not. */

  // do not close file here, postpone until it terminates
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:
        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.
        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.
   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

#ifdef VM
      // Lazy load. . .
      struct thread *curr = thread_current ();
      ASSERT (pagedir_get_page(curr->pagedir, upage) == NULL); 

      if (! vm_supt_install_filesys(curr->supt, upage,
            file, ofs, page_read_bytes, page_zero_bytes, writable) ) {
        return false;
      }
#else
      /* Get a page of memory. */
      uint8_t *kpage = vm_frame_allocate (PAL_USER, upage);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          vm_frame_free (kpage);
          return false;
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable))
        {
          vm_frame_free (kpage);
          return false;
        }
#endif

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
#ifdef VM
      ofs += PGSIZE;
#endif
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp)
{
  uint8_t *kpage;
  bool success = false;

  // upage address is the first segment of stack.
  kpage = vm_frame_allocate (PAL_USER | PAL_ZERO, PHYS_BASE - PGSIZE);
  if (kpage != NULL)
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        vm_frame_free (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  bool success = (pagedir_get_page (t->pagedir, upage) == NULL);
  success = success && pagedir_set_page (t->pagedir, upage, kpage, writable);
#ifdef VM
  success = success && vm_supt_install_frame (t->supt, upage, kpage);
#endif
  return success;
}

#ifdef VM
bool expand_stack (struct supplemental_page_table *supt, void *upage){
    struct supplemental_page_table_entry *supte = 
        (struct supplemental_page_table_entry *)malloc(sizeof(struct supplemental_page_table_entry));
    supte -> upage = upage;
    supte -> kpage = NULL;
    supte -> status = ALL_ZERO;
    supte -> dirty = false;

    struct hash_elem *prev = hash_insert(&supt->page_map, &supte->elem);
    if(prev == NULL)
        return true;
    else {
        PANIC ("Duplicated Supplementary Page Table Entry for zero page");
        return false;
    }
}

bool handle_mm_fault(struct supplemental_page_table *supt, uint32_t *pagedir, void *upage){
    //1. Check the validity of memory reference.
    struct supplemental_page_table_entry *supte;
    supte = vm_supt_look_up(supt, upage);
    if(supte == NULL)
        return false;

	//If already loaded
    if(supte->status == ON_FRAME)
        return true;
    
    //2. Obtain a frame to store the page.
    void *frame_page = vm_frame_allocate(PAL_USER, upage);
    if(frame_page == NULL){
        return false;
    }

    //3. Fetch the data into the frame.
    bool writable = true;
    switch(supte->status){
        case ALL_ZERO:
            memset(frame_page, 0 , PGSIZE);
            break;
        case ON_FRAME:
            break;
        case ON_SWAP:
            //Swap in (swap disc -> data)
            vm_swap_in(supte->swap_index, frame_page);
            break;
        case FROM_FILESYS:
		  {
			int read =file_read_at(supte->file,frame_page,supte->read_bytes,supte->file_offset);
			if(read!=(int)supte->read_bytes){
				vm_frame_free(frame_page);
				return false;
			}
			ASSERT(supte->read_bytes + supte->zero_bytes == PGSIZE);
			memset(frame_page + read, 0, supte->zero_bytes);
			writable = supte->writable;
            break;
		  }
        default:
            PANIC("Exception");
    }
    //4. Find the page table entry that faults virtual address to physical page.
    if(!pagedir_set_page(pagedir, upage, frame_page, writable)){
        vm_frame_free(frame_page);
        return false;
    }
    supte->kpage = frame_page;
    supte->status = ON_FRAME;

    pagedir_set_dirty(pagedir, frame_page, false);

    return true;
}

void preload(const void *buffer, size_t size)
{
  struct supplemental_page_table *supt = thread_current()->supt;
  uint32_t *pagedir = thread_current()->pagedir;

  void *upage;
  for(upage = pg_round_down(buffer); upage < buffer + size; upage += PGSIZE)
  {
    handle_mm_fault(supt, pagedir, upage);
  }
}

#endif

