#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"

struct lock filesys_lock;

static void syscall_handler (struct intr_frame *);

enum fd_search { FD_FILE, FD_DIRECTORY };
static struct file_desc* find_file_desc(struct thread *, int fd, enum fd_search flag);

#ifdef VM
mmapid_t sys_mmap(int fd, void *);
bool sys_munmap(mmapid_t);
static struct mmap_desc* find_mmap_desc(struct thread *, mmapid_t fd);
#endif

#ifdef FILESYS
bool sys_chdir(const char *filename);
bool sys_mkdir(const char *filename);
bool sys_readdir(int fd, char *filename);
bool sys_isdir(int fd);
int sys_inumber(int fd);
#endif

void
syscall_init (void) 
{
  lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void check_pointer(void* address)
{
	if(!is_user_vaddr(address))
	{
		exit(-1);
	}
}

static void
syscall_handler (struct intr_frame *f) 
{

  //Store the esp, which is needed in the page fault handler.
  thread_current()->current_esp = f->esp;

  switch(*(uint32_t *)(f->esp)){
    case SYS_HALT: //0
    {
	  shutdown_power_off();
      break;
    }

    case SYS_EXIT: //1
    {
	  check_pointer(f->esp+4);
      exit(*(uint32_t *)(f->esp + 4));
      break;
    }

    case SYS_EXEC: //2
    {
	  check_pointer(f->esp+4);
	  const char* cmd_line = (const char*)*(uint32_t*)(f->esp+4);
	  f->eax=exec(cmd_line);
	  break;
    }

    case SYS_WAIT: //3
    {
	  check_pointer(f->esp+4);
	  pid_t pid = (pid_t)*(uint32_t*)(f->esp+4);
	  f->eax = process_wait(pid);
	  break;
    }
  
    case SYS_CREATE: //4
    {
	  check_pointer(f->esp+4);
	  check_pointer(f->esp+8);
	  const char *file = (const char *)*(uint32_t*)(f->esp+4);
	  unsigned initial_size = (unsigned)(*(uint32_t*)(f->esp+8));
	  if(file==NULL){
		  exit(-1);
	  }
	  lock_acquire(&filesys_lock);
	  f->eax = filesys_create(file,initial_size);
	  lock_release(&filesys_lock);
	  break;
    }

    case SYS_REMOVE: //5
    {
	  check_pointer(f->esp+4);
	  const char *file = (const char*)*(uint32_t*)(f->esp+4);
	  if(file==NULL){
		  exit(-1);
	  }
	  lock_acquire(&filesys_lock);
	  f->eax = filesys_remove(file);
	  lock_release(&filesys_lock);
	  break;	
    }

    case SYS_OPEN: //6
	{
	  check_pointer(f->esp+4);
	  const char* file_name = (const char*)*(uint32_t*)(f->esp+4);
	  if(file_name == NULL){
			exit(-1);
	  }
	  f->eax = sys_open(file_name);
	  break;
    }

    case SYS_FILESIZE: //7
    {
	  check_pointer(f->esp+4);
	  int fd = (int)*(uint32_t*)(f->esp+4);
	  struct file_desc* file_d;
	  lock_acquire(&filesys_lock);
	  file_d = find_file_desc(thread_current(), fd, FD_FILE);
	  if(file_d == NULL) {
        lock_release (&filesys_lock);
        f->eax = -1;
      }
	  f->eax = file_length(file_d->file);
	  lock_release(&filesys_lock);
	  break;
    }

    case SYS_READ: //8
    {
	  int fd = (int)*(uint32_t*)(f->esp+4);
	  void* buffer = (void*)*(uint32_t*)(f->esp+8);
	  unsigned size = (unsigned)(*(uint32_t*)(f->esp+12));
	  check_pointer(buffer);

	  f->eax = sys_read(fd,buffer,size);
	  break;
    }

    case SYS_WRITE: //9
    { 
	  int fd = (int)*(uint32_t*)(f->esp+4);
	  const void* buffer= (void*)*(uint32_t*)(f->esp+8);
	  unsigned size = (unsigned)(*(uint32_t*)(f->esp+12));

	  f->eax = sys_write(fd,buffer,size);
	  break;
    }

    case SYS_SEEK: //10
    {
	  check_pointer(f->esp+4);
	  int fd = (int)*(uint32_t*)(f->esp+4);
	  unsigned position = (unsigned)(*(uint32_t*)(f->esp+8));
	  lock_acquire(&filesys_lock);
	  struct file_desc* file_d = find_file_desc(thread_current(), fd, FD_FILE);
	  if(file_d && file_d->file){
		file_seek(file_d->file,position);
	  }
	  else{
		return;
	  }
	  lock_release(&filesys_lock);
	  break;
    }

    case SYS_TELL://11
    {
	  check_pointer(f->esp+4);  
	  int fd = (int)*(uint32_t*)(f->esp+4);
	  lock_acquire(&filesys_lock);
	  struct file_desc* file_d = find_file_desc(thread_current(), fd, FD_FILE);
	  if(file_d && file_d->file) {
		f->eax = file_tell(file_d->file);
	  }
	  else{
		f->eax = -1;
	  }
	  lock_release(&filesys_lock);
	  break;	
    }

    case SYS_CLOSE://12
    {
	  check_pointer(f->esp+4);
	  int fd = (int)*(uint32_t*)(f->esp+4);
	  sys_close(fd);
	  break;
    }
#ifdef VM
    case SYS_MMAP:// 13
    {
	  int fd = (int)*(uint32_t*)(f->esp+4);
	  void* addr= (void*)*(uint32_t*)(f->esp+8);

      mmapid_t return_code = sys_mmap (fd, addr);
      f->eax = return_code;
      break;
    }

  case SYS_MUNMAP:// 14
    {	
	  mmapid_t mid = (mmapid_t)*(uint32_t*)(f->esp+4);
	  
      sys_munmap(mid);
      break;
    }
#endif
#ifdef FILESYS
  case SYS_CHDIR: // 15
    {
	  const char *dir = (const char*)*(uint32_t*)(f->esp+4);
      f->eax = sys_chdir(dir);
      break;
    }

  case SYS_MKDIR: // 16
    {
	  const char *dir = (const char*)*(uint32_t*)(f->esp+4);
      f->eax = sys_mkdir(dir);
      break;
    }

  case SYS_READDIR: // 17
    { 
	  int fd = (int)*(uint32_t*)(f->esp+4);
	  char *name = (char*)*(uint32_t*)(f->esp+8);
      f->eax = sys_readdir(fd, name);
      break;
    }

  case SYS_ISDIR: // 18
    { 
	  int fd = (int)*(uint32_t*)(f->esp+4);
      f->eax = sys_isdir(fd);
      break;
    }

  case SYS_INUMBER: // 19
    {
       
	  int fd = (int)*(uint32_t*)(f->esp+4);
      f->eax = sys_inumber(fd);
      break;
    }
#endif
  }
}

void exit(int status){
  printf("%s: exit(%d)\n",thread_current()->name,status);
  thread_current()->exit_status = status;

  thread_exit();
}

pid_t exec(const char *cmd_line){
  lock_acquire(&filesys_lock);
  pid_t pid = process_execute(cmd_line);
  lock_release(&filesys_lock);
  return  pid;
}

int sys_open(const char *file_name)
{
  struct file* file_opened;
  struct file_desc* fd = palloc_get_page(0);
  if (!fd) {
    return -1;
  }

  lock_acquire (&filesys_lock);
  file_opened = filesys_open(file_name);
  if (!file_opened) {
    palloc_free_page (fd);
    lock_release (&filesys_lock);
    return -1;
  }
  
  fd->file = file_opened; 

  // directory handling
  struct inode *inode = file_get_inode(fd->file);
  if(inode != NULL && inode_is_directory(inode)) {
    fd->dir = dir_open( inode_reopen(inode) );
  }
  else fd->dir = NULL;

  struct list* fd_list = &thread_current()->file_descriptors;
  if (list_empty(fd_list)) {
    fd->id = 3;
  }
  else {
    fd->id = (list_entry(list_back(fd_list), struct file_desc, elem)->id) + 1;
  }
  list_push_back(fd_list, &(fd->elem));

  lock_release (&filesys_lock);
  return fd->id;
  
}

int sys_read(int fd, void *buffer, unsigned size)
{

  int res = -1;
  struct thread* cur = thread_current();
	
  lock_acquire(&filesys_lock);
  if(fd==0){
	  unsigned i;
	  for(i=0; i<size; i++){
		  if(input_getc()=='\0'){
			  break;
		  }
	  }
	  res = i;
  }
  else if(fd>2){
	  struct file_desc* file_d = find_file_desc(cur, fd, FD_FILE);
	  if(file_d->file == NULL){
		  res = -1;
	  }
	  else{
		  if(file_d) {
#ifdef VM
			preload(buffer, size);
#endif		  
			//res = file_read(cur->fd[fd],buffer,size);
			res = file_read(file_d->file, buffer, size);
		  }
		  else{
			res = -1;
		  }
	  }
  }
  else{
	  res  = -1;
  }
  lock_release(&filesys_lock);
  return res;  
}

int sys_write(int fd, const void *buffer,unsigned size)
{

  int res = -1;
  struct thread* cur = thread_current();

  lock_acquire(&filesys_lock);
  if(fd ==1){
	  putbuf(buffer,size);
	  res = size;
  }
  else if(fd>2){
	  struct file_desc* file_d = find_file_desc(cur, fd, FD_FILE);
	  if(file_d->file==NULL){
		  res = 0;
	  }
	  else{
		  if(file_d) {
#ifdef VM
			preload(buffer, size);
#endif		  
			//res = file_write(cur->fd[fd],buffer,size);
			res = file_write(file_d->file, buffer, size);
		  }
		  else{
			res = 0;
		  }
	  }
  }
  else{
	  res = 0;
  }
  lock_release(&filesys_lock);
  return res;
}

void sys_close(int fd)
{
  lock_acquire (&filesys_lock);
  struct file_desc* file_d = find_file_desc(thread_current(), fd, FD_FILE | FD_DIRECTORY);

  if(file_d && file_d->file) {
    file_close(file_d->file);
    if(file_d->dir) dir_close(file_d->dir);
    list_remove(&(file_d->elem));
    palloc_free_page(file_d);
  }
  lock_release (&filesys_lock);
}

#ifdef VM
mmapid_t sys_mmap(int fd, void *upage) {
  if (upage == NULL || pg_ofs(upage) != 0) 
    return -1;
  if (fd <= 1) 
    return -1; 
  struct thread *cur = thread_current();

  lock_acquire (&filesys_lock);
 
  
  /* 1. Open file */
  struct file *f = NULL;
  struct file_desc* file_d = find_file_desc(thread_current(), fd, FD_FILE);
  if(file_d && file_d->file) {
    // reopen file so that it doesn't interfere with process itself
    // it will be store in the mmap_desc struct (later closed on munmap)
    f = file_reopen (file_d->file);
  }
  if(f == NULL) goto MMAP_FAIL;
	
  size_t file_size = file_length(f);
  if(file_size == 0) 
    goto MMAP_FAIL;

  /* 2. Mapping memory pages
   First, ensure that all the page address is NON-EXIESENT. */
  size_t offset;
  for (offset = 0; offset < file_size; offset += PGSIZE) {
    void *addr = upage + offset;
    if (vm_supt_has_entry(cur->supt, addr)) goto MMAP_FAIL;
  }

  /* Now, map each page to filesystem */
  for (offset = 0; offset < file_size; offset += PGSIZE) {
    void *addr = upage + offset;

    size_t read_bytes = (offset + PGSIZE < file_size ? PGSIZE : file_size - offset);
    size_t zero_bytes = PGSIZE - read_bytes;

    vm_supt_install_filesys(cur->supt, addr,
        f, offset, read_bytes, zero_bytes, true);
  }

  /* 3. Assign mmapid */
  mmapid_t mid;
  if (! list_empty(&cur->mmap_list)) {
    mid = list_entry(list_back(&cur->mmap_list), struct mmap_desc, elem)->id + 1;
  }
  else mid = 1;

  struct mmap_desc *mmap_d = (struct mmap_desc*) malloc(sizeof(struct mmap_desc));
  mmap_d->id = mid;
  mmap_d->file = f;
  mmap_d->addr = upage;
  mmap_d->size = file_size;

  list_push_back (&cur->mmap_list, &mmap_d->elem);

  lock_release (&filesys_lock);
  return mid;

MMAP_FAIL:
  lock_release (&filesys_lock);
  return -1;
}

bool sys_munmap(mmapid_t mid)
{
  struct thread *curr = thread_current();
  struct mmap_desc *mmap_d = find_mmap_desc(curr, mid);

  if(mmap_d == NULL) { // not found such mid
    return false; 
  }

  lock_acquire (&filesys_lock);
  {
    // Iterate through each page
    size_t offset, file_size = mmap_d->size;
    for(offset = 0; offset < file_size; offset += PGSIZE) {
      void *addr = mmap_d->addr + offset;
      size_t bytes = (offset + PGSIZE < file_size ? PGSIZE : file_size - offset);
      vm_supt_mm_unmap (curr->supt, curr->pagedir, addr, mmap_d->file, offset, bytes);
    }

    // Free resources, and remove from the list
    list_remove(& mmap_d->elem);
    file_close(mmap_d->file);
    free(mmap_d);
  }
  lock_release (&filesys_lock);

  return true;
}
#endif

#ifdef VM
static struct mmap_desc* find_mmap_desc(struct thread *t, mmapid_t mid)
{
  ASSERT (t != NULL);

  struct list_elem *e;

  if (! list_empty(&t->mmap_list)) {
    for(e = list_begin(&t->mmap_list);
        e != list_end(&t->mmap_list); e = list_next(e))
    {
      struct mmap_desc *desc = list_entry(e, struct mmap_desc, elem);
      if(desc->id == mid) {
        return desc;
      }
    }
  }

  return NULL; // not found
}
#endif

static struct file_desc*
find_file_desc(struct thread *t, int fd, enum fd_search flag)
{
  ASSERT (t != NULL);

  if (fd < 3) {
    return NULL;
  }

  struct list_elem *e;

  if (! list_empty(&t->file_descriptors)) {
    for(e = list_begin(&t->file_descriptors);
        e != list_end(&t->file_descriptors); e = list_next(e))
    {
      struct file_desc *desc = list_entry(e, struct file_desc, elem);
      if(desc->id == fd) {
        
        if (desc->dir != NULL && (flag & FD_DIRECTORY) )
          return desc;
        else if (desc->dir == NULL && !(flag & FD_FILE) )
          return desc;
      }
    }
  }

  return NULL; // not found
}

#ifdef FILESYS

bool sys_chdir(const char *dir)
{
  bool ret;

  lock_acquire (&filesys_lock);
  ret = dir_chdir(dir);
  lock_release (&filesys_lock);

  return ret;
}

bool sys_mkdir(const char *dir)
{
  bool ret;

  lock_acquire (&filesys_lock);
  ret = filesys_create_dir(dir);
  lock_release (&filesys_lock);

  return ret;
}

bool sys_readdir(int fd, char *name)
{
  struct file_desc* file_d;
  bool ret = false;

  lock_acquire (&filesys_lock);
  file_d = find_file_desc(thread_current(), fd, FD_DIRECTORY);
  if (file_d == NULL){
	lock_release(&filesys_lock);
	return ret;
  } 

  ret = dir_readdir (file_d->dir, name);

  lock_release (&filesys_lock);
  return ret;
}

bool sys_isdir(int fd)
{
  lock_acquire (&filesys_lock);

  struct file_desc* file_d = find_file_desc(thread_current(), fd, FD_FILE | FD_DIRECTORY);
  bool ret = inode_is_directory (file_get_inode(file_d->file));

  lock_release (&filesys_lock);
  return ret;
}

int sys_inumber(int fd)
{
  lock_acquire (&filesys_lock);

  struct file_desc* file_d = find_file_desc(thread_current(), fd, FD_FILE | FD_DIRECTORY);
  int ret = (int) inode_get_inumber (file_get_inode(file_d->file));

  lock_release (&filesys_lock);
  return ret;
}

#endif
