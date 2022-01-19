#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "user/syscall.h"
#include "userprog/process.h"
#include "devices/input.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

struct lock file_lock;

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
}
void check_pointer(void*address)
{	
	if(!is_user_vaddr(address))
	{	
		exit(-1);
	}
}

static void
syscall_handler (struct intr_frame *f) 
{
  switch (*(uint32_t *)(f->esp)) {
    case SYS_HALT:
	  shutdown_power_off();
      break;
    case SYS_EXIT:
	  {
		check_pointer(f->esp+4);
		exit(*(uint32_t *)(f->esp + 4));
		break;
	  }
    case SYS_EXEC:
	  {
		check_pointer(f->esp+4);
	    const char* cmd_line = (const char*)*(uint32_t*)(f->esp+4);
		f->eax=exec(cmd_line);
		break;
	  }
    case SYS_WAIT:
	  {
		check_pointer(f->esp+4);
		pid_t pid = (pid_t)*(uint32_t*)(f->esp+4);
		f->eax = process_wait(pid);
		break;
	  }
    case SYS_READ:
	  {
		int fd = (int)*(uint32_t*)(f->esp+4);
		void* buffer = (void*)*(uint32_t*)(f->esp+8);
		unsigned size = (unsigned)(*(uint32_t*)(f->esp+12));
		check_pointer(buffer);

		f->eax = read(fd,buffer,size);
		break;
	  }
    case SYS_WRITE:
	  {	  
		  int fd = (int)*(uint32_t*)(f->esp+4);
		  const void* buffer= (void*)*(uint32_t*)(f->esp+8);
		  unsigned size = (unsigned)(*(uint32_t*)(f->esp+12));
		  		  
		  f->eax = write(fd,buffer,size);
		  break;
	  }
	case SYS_FIBO:
	  {
		  int n = (int)*(uint32_t*)(f->esp+4);
		  f->eax = fibonacci(n);
		  break;	
	  }
	case SYS_MAX:
	  {
		  int a = (int)*(uint32_t*)(f->esp+4);
	      int b = (int)*(uint32_t*)(f->esp+8);
		  int c = (int)*(uint32_t*)(f->esp+12);
		  int d = (int)*(uint32_t*)(f->esp+16);
		  f->eax = max_of_four_int(a,b,c,d);
		  break;
	  } 
	case SYS_CREATE:
	  {
		check_pointer(f->esp+4);
		check_pointer(f->esp+8);
		const char *file = (const char *)*(uint32_t*)(f->esp+4);
		unsigned initial_size = (unsigned)(*(uint32_t*)(f->esp+8));
		if(file==NULL){
			exit(-1);
		}
		f->eax = filesys_create(file,initial_size);
		break;
	  }
	case SYS_REMOVE:
	  {
		check_pointer(f->esp+4);
		const char *file = (const char*)*(uint32_t*)(f->esp+4);
		if(file==NULL){
			exit(-1);
		}
		f->eax = filesys_remove(file);
		break;
	  }
	case SYS_OPEN:
	  {
		check_pointer(f->esp+4);
		const char* file_name = (const char*)*(uint32_t*)(f->esp+4);
		if(file_name == NULL){
			exit(-1);
		}
		
		f->eax = open(file_name);
		break;
	  }
	case SYS_FILESIZE:
	  {
		check_pointer(f->esp+4);
		int fd = (int)*(uint32_t*)(f->esp+4);
		f->eax = file_length(thread_current()->fd[fd]);
		break;
	  }
	case SYS_SEEK:
	  {
		check_pointer(f->esp+4);
		int fd = (int)*(uint32_t*)(f->esp+4);
		unsigned position = (unsigned)(*(uint32_t*)(f->esp+8));
		file_seek(thread_current()->fd[fd],position);
		break;	
	  }
	case SYS_TELL:
	  {
		check_pointer(f->esp+4);  
		int fd = (int)*(uint32_t*)(f->esp+4);
		f->eax = file_tell(thread_current()->fd[fd]);
		break;
	  }
	case SYS_CLOSE:
	  { 
		check_pointer(f->esp+4);
		int fd = (int)*(uint32_t*)(f->esp+4);
		close(fd);
		break;
	  }
  }
}

void exit (int status) {
  printf("%s: exit(%d)\n",thread_name(),status);
  thread_current()->exit_status= status;
  thread_exit ();
}

pid_t exec(const char* cmd_lines){
	return process_execute(cmd_lines);
}

int fibonacci(int n){
	int f1=1, f2=1;
	int res;

	if(n<0){
		return 0;
	}
	if(n<3){
		return 1;
	}
	for(int i=3; i<=n; i++){
		res = f1 + f2;
		f1 = f2;
		f2 = res;
	}
	return res;
}

int max_of_four_int(int a, int b, int c, int d){
	int max = a;
	int maximus[3] = {b,c,d};
	for(int i=0; i<3; i++){
		if(max < maximus[i]){
			max = maximus[i];
		}
	}
	return max;
}

int open(const char* file){	
	int res = -1;
	struct file* f;
	struct thread* cur = thread_current();

	lock_acquire(&file_lock);
	f = filesys_open(file);
	if(f==NULL){
		res =  -1;
	}
	else{
		for(int i=3; i<131; i++){
			if(cur->fd[i]==NULL){
				if(!strcmp(cur->name,file)){
					file_deny_write(f);
				}
				cur->fd[i] = f;
				res = i;
				break;
			}
		}
	}
	lock_release(&file_lock);
	return res;
}

void close(int fd){
	struct file* fp;

	fp = thread_current()->fd[fd];
	if(fp==NULL){
		exit(-1);
	}
    thread_current()->fd[fd] = NULL;
	file_close(fp);
}

int read(int fd, void* buffer, unsigned size){
	int res = -1;
	struct thread* cur = thread_current();
	
	lock_acquire(&file_lock);
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
		if(cur->fd[fd] == NULL){
			res = -1;
		}
		else{
			res = file_read(cur->fd[fd],buffer,size);
		}
	}
	else{
		res  = -1;
	}
	lock_release(&file_lock);
	return res;
}

int write(int fd, const void* buffer, unsigned size){	
	int res = -1;
	struct thread* cur = thread_current();

	lock_acquire(&file_lock);
	if(fd ==1){
		putbuf(buffer,size);
		res = size;
	}
	else if(fd>2){
		if(cur->fd[fd]==NULL){
			res = 0;
		}
		else{
			res = file_write(cur->fd[fd],buffer,size);
		}
	}
	else{
		res = 0;
	}
	lock_release(&file_lock);
	return res;
}

