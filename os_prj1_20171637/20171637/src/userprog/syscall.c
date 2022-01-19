#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "user/syscall.h"
#include "userprog/process.h"
#include "devices/input.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
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
		int fd = (int)*(uint32_t*)f->esp+4;
		unsigned size = (unsigned)(*(uint32_t*)(f->esp+12));
		if(fd==0){
			unsigned i;
			for(i=0; i<size; i++){
				if(input_getc()=='\0'){
					break;
				}
			}
			f->eax= i;
		}
		else{
			f->eax = -1;
		}
		break;
	  }
    case SYS_WRITE:
	  {		
		  int fd = (int)*(uint32_t*)(f->esp+4);
		  const void* buffer= (void*)*(uint32_t*)(f->esp+8);
		  unsigned size = (unsigned)(*(uint32_t*)(f->esp+12));
		  if(fd ==1){
			putbuf(buffer,size);
			f->eax = size;
		  }
		  else{
			f->eax = -1;
		  }
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
  }

  // thread_exit ();
}

void exit (int status) {
  printf("%s: exit(%d)\n",thread_name(),status);
  thread_current()->exit_status= status;
  thread_current()->fin = true;
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
