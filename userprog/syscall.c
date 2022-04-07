#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

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
			int status = f->R.rdi;
			struct thread *curr = thread_current();
			curr->exit_status = status;
			thread_exit();
			lock_release(curr->exit_wait_lock);
			break;
		
		case SYS_FORK :
			char *thread_name = f->R.rdi;
			tid_t child_pid = process_fork(thread_name, f);
			f->R.rax = child_pid;
			break;
		
		case SYS_EXEC :
			char *cmd_line = f->R.rdi;
			int result = process_exec(cmd_line);

			if (result == -1)
			{
				struct thread *cur = thread_current();
				cur->exit_status = -1;
				thread_exit();
				printf ("%s: exit(%d)\n", curr->thread_name, curr->exit_status);
				lock_relase(cur->exit_wait_lock);

			}
			break;
		
		case SYS_WAIT :
			tid_t child_id = f->R.rdi;
			f->R.rax = process_wait(child_id);
			break;
		
		case SYS_CREATE : 
			char *file = f->R.rdi;
			unsigned size = f->R.rsi;
			if (is_valid_access(file)) 
			{
				filesys_create(file, size);
				f->R.rax = true;
			}	
			else 
			{
				f->R.rax = false;
			}
			break;
		
		case SYS_REMOVE :
			char *file = f->R.rdi;
			if (is_valid_access(file))
			{
				filesys_remove(file);
				f->R.rax = true;
			}
			else 
			{
				f->R.rax = false;
			}
			break;
		
		case SYS_OPEN :
			char *file = f->R.rdi;
			struct thread *cur = thread_current();
			if (is_valid_access(file)){
				
				struct file *file_open = filesys_open(file);
				if (file_open != NULL)
				{
					struct fd_entity e = cur->file_table[cur->next_fd];
					e.file = file_open;
					e.fd = cur->next_fd;
					e.is_open = true;

					f->R.rax = e.fd;
					cur->next_fd++;

				}
				else
				{
					f->R.rax = -1;
				}
			}
			else 
			{
				f->R.rax = -1;
			}
			break;
		
		case SYS_FILESIZE :
			int fd = f->R.rdi;
			struct thread *cur = thread_current();

			if ((cur->file_table)[fd].is_open) 
			{
				struct file *file = (cur->file_table)[fd].file;
				int length = file_length(file);
				f->R.rax = length;
			}
			else 
			{
				f->R.rax = 0;
			}
			break;
		
		case SYS_READ :
			int fd = f->R.rdi;
			void *buffer = f->R.rsi;
			unsigned size = f->R.rdx;
			struct thread *cur = thread_current();
			struct fd_entity e = (cur->file_table)[fd];
			struct lock *file_lock;

			if (is_valid_access(buffer))
			{
				if (e.is_open && e.file != NULL)
				{
					if (e.file == stdout)
					{
						f->R.rax = -1;
					}
					else
					{
						lock_acquire(file_lock);
						int read_byte = 0;
						if (e.file == stdin)
						{
							for (int i = 0; i < size ; i++)
							{
								if (input_getc() == EOF)
								{
									f->R.rax = read_byte;
									break;
								}  
								else 
								{
									read_byte++;
								}
							}
						}
						else 
						{
							read_byte = file_read(e.file, buffer, size);
							f->R.rax = read_byte;
						}
						lock_release(file_lock);
					}
				}
				else 
				{
					f->R.rax = -1;
				}
			}
			else
			{
				f->R.rax = -1;
			}
			break;
		
		case SYS_WRITE :
			int fd = f->R.rdi;
			void *buffer = f->R.rsi;
			unsigned size = f->R.rdx;
			struct thread *cur = thread_current();
			struct fd_entity e = (cur->file_table)[fd];
			struct lock *file_lock;

			if (is_valid_access(buffer))
			{
				if (e.is_open && e.file != NULL)
				{
					if (e.file == stdin)
					{
						f->R.rax = -1;
					}
					else
					{
						lock_aquire(file_lock);
						int write_byte = 0;

						if (e.file == stdout)
						{
							write_byte = putbuf();
							f->R.rax = write_byte;
						}
						else
						{
							write_byte = file_write(file,buffer,size);
							f->R.rax = write_byte;
						}

						lock_release(file_lock);
					}
				}
				else
				{
					f->R.rax = -1;
				}
			}
			else 
			{
				f->R.rax = -1;
			}
			break;
		
		case SYS_SEEK : 
			int fd = f->R.rdi;
			unsigned new_pos = f->R.rsi;
			struct thread *cur = thread_current();
			struct fd_entity e = cur->file_table[fd];
			

			if (e.is_open && e.file != NULL)
			{
				e.file->pos = new_pos;	
				
			}

			break;
		
		case SYS_TELL :
			int fd = f->R.rdi;
			struct thread *cur = thread_current();
			struct fd_entity e = cur->file_table[fd];
			unsigned pos;

			if (e.is_open && e.file != NULL)
			{
				pos = file_tell(e.file);
				f->R.rax = pos;
			}
			
			break;
		
		case SYS_CLOSE :
			int fd = f->R.rdi;
			struct thread *cur = thread_current();
			struct fd_entity e = cur->file_table[fd];

			if (e.is_open && e.file != NULL)
			{
				file_close(e.file);
				e.file = NULL;
				e.is_open = false;
			}

			break;
	}

	printf ("system call!\n");
	thread_exit ();
}

bool is_valid_access(void * user_provided_pointer)
{
	if (user_provided_pointer == NULL) return false;
	if (is_kernel_vaddr(user_provided_pointer)) return false;

	void *page_addr = pg_round_down(user_provided_pointer);
	return pml4_is_accessed(thread_current()->pml4, page_addr);

}