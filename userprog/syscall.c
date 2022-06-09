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
#include "filesys/directory.h"
#include <string.h>
#include "filesys/inode.h"

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
			lock_acquire(&file_lock);
			is_valid_access(f->R.rdi);
			f->R.rax = filesys_create(f->R.rdi, f->R.rsi); 
			lock_release(&file_lock);
			break;
		}

		case SYS_REMOVE :
		{	
			lock_acquire(&file_lock);
			is_valid_access(f->R.rdi);
			f->R.rax = filesys_remove(f->R.rdi);
			lock_release(&file_lock);
			break;
		}

		case SYS_OPEN :
		{		
			lock_acquire(&file_lock);
			struct thread *cur = thread_current();
			is_valid_access(f->R.rdi);	
			struct file *file_o = NULL;
			struct dir *dir_o = NULL;
			bool is_file;
			
			char *copy = palloc_get_page(PAL_ZERO);
			strlcpy(copy, f->R.rdi, strlen(f->R.rdi)+1);

			char *file_name = malloc(NAME_MAX + 1);
			
			struct dir *dir = dir_parse(copy, file_name);
			
			struct inode *inode = NULL;
			
			if (dir == NULL) f->R.rax = -1;
			else
			{
				if (dir_lookup(dir,file_name, &inode) == false) f->R.rax = -1;
				else
				{
					if (inode_is_file(inode))
					{
						file_o = file_open(inode);
						is_file = true;
					}
					else
					{
						dir_o = dir_open(inode);
						is_file = false;
					}
						
					if (!(file_o == NULL && dir_o == NULL))
					{
						struct file_table_entity *e = malloc(sizeof(struct file_table_entity));
						if (e==NULL) 
						{
							f->R.rax = -1;
							if (is_file) file_close(file_o);
							else dir_close(dir_o);
						}
						else
						{
							if (is_file) 
							{
								e->file = file_o;
								e->is_file = true;
							}
							else 
							{
								e->dir = dir_o;
								e->is_file = false;
							}


							int find_fd = 2; 
							struct list_elem *curr_elem= list_begin(&cur->file_table);
							struct list_elem *last_elem = list_end(&cur->file_table);

							if (curr_elem == last_elem)
							{
								e->fd = find_fd;
								list_push_front(&cur->file_table, &e->elem);
								f->R.rax = 2;
							}
							else
							{
								while (curr_elem != last_elem)
								{
									struct file_table_entity *traverse = list_entry(curr_elem, struct file_table_entity, elem);
									if (traverse->fd == find_fd) 
									{
										find_fd++;
										if (list_next(curr_elem) == last_elem)
										{
											e->fd = find_fd;
											list_push_back(&cur->file_table, &e->elem);
											f->R.rax = e->fd;
											break;
										}
									}	
									else
									{
										e->fd = find_fd;
										list_insert(&traverse->elem, &e->elem);
										f->R.rax = e->fd;
										break;
									}
									curr_elem = list_next(curr_elem);
								}
							}	
						}	

					}
					else
					{
						f->R.rax = -1;
					}
				}	
			}
			free(file_name);
			palloc_free_page(copy);
			lock_release(&file_lock);
			break;
		}

		case SYS_FILESIZE :
		{
			lock_acquire(&file_lock);
			int fd = f->R.rdi;
			struct thread *cur = thread_current();
			struct file *f_size = NULL;

			struct list_elem *curr = list_begin(&cur->file_table);
			struct list_elem *last = list_end(&cur->file_table);
			
			while(curr != last)
			{
				struct file_table_entity *e = list_entry(curr, struct file_table_entity, elem);
				if (e->fd == fd) f_size = e->file;
				curr = list_next(curr);
			}
			
			if (f_size != NULL)
			{
				f->R.rax = file_length(f_size);
			}
			else 
			{
				f->R.rax = -1;
			}
			lock_release(&file_lock);
			break;
		}

		case SYS_READ :
		{
			int fd = f->R.rdi;
			void *buffer = f->R.rsi;
			unsigned size = f->R.rdx;
			is_valid_access(buffer);

			struct thread *cur = thread_current();
			struct file *f_read = NULL;
			bool is_file;

			if (0 <= fd)
			{
				struct list_elem *curr = list_begin(&cur->file_table);
				struct list_elem *last = list_end(&cur->file_table);
			
				while(curr != last)
				{
					struct file_table_entity *e = list_entry(curr, struct file_table_entity, elem);
					if (e->fd == fd) 
					{
						f_read = e->file;
						is_file = e->is_file;
						break;
					}
					curr = list_next(curr);
				}

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
					if (is_file == false) read_byte = -1;
					lock_acquire(&file_lock);
					read_byte = file_read(f_read, buffer, size);
					lock_release(&file_lock);
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
			struct file *f_write = NULL;
			bool is_file;

			struct thread *cur = thread_current();

			if (0<=fd )
			{
				struct list_elem *curr = list_begin(&cur->file_table);
				struct list_elem *last = list_end(&cur->file_table);
			
				while(curr != last)
				{
					struct file_table_entity *e = list_entry(curr, struct file_table_entity, elem);
					if (e->fd == fd) 
					{
						f_write = e->file;
						is_file = e->is_file;
					}
					curr = list_next(curr);
				}

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
					else if (is_file == false) write_byte = -1;
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
			lock_acquire(&file_lock);
			int fd = f->R.rdi;
			unsigned new_pos = f->R.rsi;
			struct thread *cur = thread_current();
			struct file *f_seek = NULL;
			
			if (0 <= fd )
			{
				struct list_elem *curr = list_begin(&cur->file_table);
				struct list_elem *last = list_end(&cur->file_table);
			
				while(curr != last)
				{
					struct file_table_entity *e = list_entry(curr, struct file_table_entity, elem);
					if (e->fd == fd) f_seek = e->file;
					curr = list_next(curr);
				}

				if (f != NULL)
				{
					file_seek(f_seek, new_pos);
				}
			}
			lock_release(&file_lock);
			break;
		}
		case SYS_TELL :
		{
			lock_acquire(&file_lock);
			int fd = f->R.rdi;
			struct thread *cur = thread_current();
			struct file *f_tell = NULL;

			if (0 <= fd)
			{
				struct list_elem *curr = list_begin(&cur->file_table);
				struct list_elem *last = list_end(&cur->file_table);
			
				while(curr != last)
				{
					struct file_table_entity *e = list_entry(curr, struct file_table_entity, elem);
					if (e->fd == fd) f_tell = e->file;
					curr = list_next(curr);
				}

				if (f != NULL)
				{
					f->R.rax = file_tell(f_tell);
				}
			}
			lock_release(&file_lock);
			break;
		}
		case SYS_CLOSE :
		{
			
			lock_acquire(&file_lock);
			int fd = f->R.rdi;
			struct thread *cur = thread_current();
			

			if (1<fd)
			{
				struct list_elem *curr = list_begin(&cur->file_table);
				struct list_elem *last = list_end(&cur->file_table);
			
				while(curr != last)
				{
					struct file_table_entity *e = list_entry(curr, struct file_table_entity, elem);
					if (e->fd == fd) 
					{
						if (e->is_file) file_close(e->file);
						else dir_close(e->dir);
						
						list_remove(&e->elem);
						free(e);
						break;
					}	
					curr = list_next(curr);
				}
			}
			lock_release(&file_lock);
			break;
		}
		case SYS_CHDIR:
		{
			char *path_name = f->R.rdi;
			is_valid_access(path_name);
			
			char *copy = malloc(strlen(path_name)+1);
			strlcpy(copy, path_name,strlen(path_name)+1);

			char *file_name = malloc(NAME_MAX + 1);
			struct dir *dir = dir_parse(copy, file_name);
			if (dir == NULL) f->R.rax = 0;
			else
			{
				
				struct inode *inode;
				if( !dir_lookup(dir, file_name, &inode) ) 
				{
					f->R.rax = 0;
				}		
				else
				{
					if (inode_is_file(inode)) 
					{
						f->R.rax = 0;
					}
					else
					{
						struct dir *new = dir_open(inode);
						dir_close(thread_current()->current_dir);
						thread_current()->current_dir = new;
						f->R.rax = 1;
					}
				}	
			}
			free(file_name);
			free(copy);

			break;
		}
		case SYS_MKDIR:
		{
			
			char *path_name = f->R.rdi;
			is_valid_access(path_name);
			f->R.rax = filesys_create_dir(path_name, 512);
			
			break;
		}
		case SYS_READDIR:
		{
			
			int fd = f->R.rdi;
			char *name = f->R.rsi;
			struct thread *cur = thread_current();
			is_valid_access(name);
			bool success;
			
			struct dir *dir;
			if (1<fd)
			{
				struct list_elem *curr = list_begin(&cur->file_table);
				struct list_elem *last = list_end(&cur->file_table);
			
				while(curr != last)
				{
					struct file_table_entity *e = list_entry(curr, struct file_table_entity, elem);
					if (e->fd == fd) 
					{
						if (!e->is_file) 
						{
							dir = e->dir;
							
							success = dir_readdir(dir, name);
							if (strcmp(name, ".") == 0) success = dir_readdir(dir,name);
							if (strcmp(name, "..") == 0) success = dir_readdir(dir,name);
							
							f->R.rax = success;
						}
						break;
					}	
					curr = list_next(curr);
				}
				if (curr == last) f->R.rax = 0;
			}


			break;
		}
		case SYS_ISDIR:
		{
			int fd = f->R.rdi;
			struct thread *cur = thread_current();
			if (1<fd)
			{
				struct list_elem *curr = list_begin(&cur->file_table);
				struct list_elem *last = list_end(&cur->file_table);
			
				while(curr != last)
				{
					struct file_table_entity *e = list_entry(curr, struct file_table_entity, elem);
					if (e->fd == fd) 
					{
						if (e->is_file) f->R.rax = 0;
						else f->R.rax = 1;
						break;
					}	
					curr = list_next(curr);
				}
				if (curr == last) f->R.rax = 0;
			}

			break;
		}
		case SYS_INUMBER:
		{
			int fd = f->R.rdi;
			struct thread *cur = thread_current();
			if (1<fd)
			{
				struct list_elem *curr = list_begin(&cur->file_table);
				struct list_elem *last = list_end(&cur->file_table);
			
				while(curr != last)
				{
					struct file_table_entity *e = list_entry(curr, struct file_table_entity, elem);
					if (e->fd == fd) 
					{
						if (e->is_file) f->R.rax = file_inode_sector(e->file);
						else f->R.rax = dir_inode_sector(e->dir);
						break;
					}	
					curr = list_next(curr);
				}
				if (curr == last) f->R.rax = -1;
			}
			break;
		}
		case SYS_SYMLINK:
		{
			char *target = f->R.rdi;
			char *linkpath = f->R.rsi;
			is_valid_access(target);
			is_valid_access(linkpath);

			char *copy = palloc_get_page(PAL_ZERO);
			strlcpy(copy, target,strlen(target)+1);

			char file_name[NAME_MAX + 1];

			struct dir *cur_dir = thread_current()->current_dir;
			struct dir *target_dir = dir_parse(copy, file_name);

			struct inode *inode;
			if (dir_lookup(target_dir, file_name, &inode))
			{
				dir_add(cur_dir, linkpath, inode_get_inumber(inode));
			}
			else
			{
				f->R.rax = -1;
			}
			
			palloc_free_page(copy);
			break;
		}
	}
	
}


void is_valid_access(void *va)
{
	if (va == NULL) exit(-1);
	if (is_kernel_vaddr(va))  exit(-1);

	void *page = pml4_get_page(thread_current()->pml4,va);
	if (page==NULL) 
	{
		
		exit(-1);
	}
	return;

}

void exit(int status)
{
	struct thread *curr = thread_current();
	curr->exit_status = status;
	printf("%s: exit(%d)\n", curr->name, curr->exit_status);
	thread_exit();
	
}

