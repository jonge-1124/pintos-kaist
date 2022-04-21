#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/palloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "userprog/process.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void is_valid_access(void *user_provided_pointer);
void exit(int status);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
	lock_init(&file_lock);	
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	
	uint64_t sys_num = f->R.rax;
	
	
	switch(sys_num){
		case SYS_HALT : 
			
			power_off();
			break;
		
		case SYS_EXIT : 
		{
			exit(f->R.rdi);
			break;
		}
		
		case SYS_FORK :
		{	
			is_valid_access(f->R.rdi);
			f->R.rax = process_fork(f->R.rdi, f);
			break;
		}

		case SYS_EXEC :
		{	
			is_valid_access(f->R.rdi);	

			char *fn_copy = palloc_get_page(PAL_ZERO);
			if (fn_copy == NULL) exit(-1);
			strlcpy(fn_copy, f->R.rdi, strlen(f->R.rdi)+1);
			
			if (process_exec(fn_copy) == -1) exit(-1);

			
			break;
		}

		case SYS_WAIT :
		{
			f->R.rax = process_wait(f->R.rdi);
			break;
		}

		case SYS_CREATE : 
		{	
			is_valid_access(f->R.rdi);
			f->R.rax = filesys_create(f->R.rdi, f->R.rsi); 
			break;
		}

		case SYS_REMOVE :
		{	
			is_valid_access(f->R.rdi);
			f->R.rax = filesys_remove(f->R.rdi);
			break;
		}

		case SYS_OPEN :
		{		
			struct thread *cur = thread_current();
			is_valid_access(f->R.rdi);	
			struct file *file_o = filesys_open(f->R.rdi);
		
				
			if (file_o != NULL)
			{
				
				for (int i = 2; i < FILE_LIMIT; i++)
				{
					if (cur->file_table[i] == NULL) 
					{
						cur->file_table[i]= file_o;
						f->R.rax = i;
						break;
					}
					//file table is full, so close the given file
					if (i == FILE_LIMIT - 1 && cur->file_table[i] != NULL) 
					{
						file_close(file_o);
						
						f->R.rax = -1;
					}
				}	
			}
			else
			{
				f->R.rax = -1;
			}
			
			break;
		}

		case SYS_FILESIZE :
		{
			int fd = f->R.rdi;
			struct thread *cur = thread_current();
			struct file *f_size = cur->file_table[fd];
			
			if (f_size != NULL)
			{
				f->R.rax = file_length(f_size);
			}
			else 
			{
				f->R.rax = -1;
			}
			break;
		}

		case SYS_READ :
		{
			int fd = f->R.rdi;
			void *buffer = f->R.rsi;
			unsigned size = f->R.rdx;
			is_valid_access(buffer);
			struct thread *cur = thread_current();

			if (0 <= fd  && fd < FILE_LIMIT)
			{
				struct file *f_read = cur->file_table[fd];
				int read_byte = 0;

				if (fd == 0)
				{
					lock_acquire(&file_lock);
					for (int i = 0; i < size ; i++)
					{
						if (input_getc() == '\0') break;
						else read_byte++;
					}
					lock_release(&file_lock);
					
				}
				else if (fd == 1)
				{
					read_byte = -1;
				}
				else
				{
					if (f_read == NULL) read_byte = -1;
					else
					{
						lock_acquire(&file_lock);
						read_byte = file_read(f_read, buffer, size);
						lock_release(&file_lock);
					}
				}
				
				f->R.rax = read_byte;
			}
			else f->R.rax = -1;		
			break;
		}
		case SYS_WRITE :
		{
			int fd = f->R.rdi;
			void *buffer = f->R.rsi;
			unsigned size = f->R.rdx;
			is_valid_access(buffer);

			struct thread *cur = thread_current();

			if (0<=fd && fd<FILE_LIMIT)
			{
				struct file *f_write = cur->file_table[fd];
				int write_byte = 0;

				if (fd == 0) write_byte = -1;
				else if (fd == 1) 
				{		
					lock_acquire(&file_lock);
					putbuf(buffer, size);
					lock_release(&file_lock);
					write_byte = size;
						
				}
				else 
				{
					if (f_write == NULL) write_byte = -1;
					else
					{
						lock_acquire(&file_lock);
						write_byte = file_write(f_write, buffer, size);
						lock_release(&file_lock);
					}

				}	
				
				f->R.rax = write_byte;
			}
			else f->R.rax = -1;	
			break;
		}
		case SYS_SEEK : 
		{
			int fd = f->R.rdi;
			unsigned new_pos = f->R.rsi;
			struct thread *cur = thread_current();
			
			if (0 <= fd && fd <= FILE_LIMIT)
			{
				struct file *f_seek = cur->file_table[fd];
				if (f != NULL)
				{
					file_seek(f_seek, new_pos);
				}
			}
			break;
		}
		case SYS_TELL :
		{
			int fd = f->R.rdi;
			struct thread *cur = thread_current();

			if (0 <= fd && fd <= FILE_LIMIT)
			{
				struct file *f_tell = cur->file_table[fd];
				if (f != NULL)
				{
					f->R.rax = file_tell(f_tell);
				}
			}
			break;
		}
		case SYS_CLOSE :
		{
			
			int fd = f->R.rdi;
			struct thread *cur = thread_current();
			if (1<fd && fd < FILE_LIMIT)
			{
				file_close(cur->file_table[fd]);
				cur->file_table[fd] = NULL;
			}
			
			break;
		}
	}
	
}


void is_valid_access(void *va)
{
	if (va == NULL) exit(-1);
	if (is_kernel_vaddr(va))  exit(-1);

	void *page = pml4_get_page(thread_current()->pml4,va);
	if (page==NULL) exit(-1);

	return;

}

void exit(int status)
{
	struct thread *curr = thread_current();
	curr->exit_status = status;
	printf("%s: exit(%d)\n", curr->name, curr->exit_status);
	thread_exit();
	
}