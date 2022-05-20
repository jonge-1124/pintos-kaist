/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "threads/vaddr.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* Do the mmap */
struct mmap_info {
	struct file *file;
	size_t offset;
	bool mmap;
	bool munmap;
	int page_num;
};

/* The initializer of file vm */
void
vm_file_init (void) {

}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;
	struct mmap_info *aux = page->uninit.aux;

	struct file_page *file_page = &page->file;
	file_page->file = aux->file;
	file_page->offset = aux->offset;
	file_page->mmap = aux->mmap;
	file_page->munmap = aux->munmap;
	file_page->page_num = aux->page_num;

	file_backed_swap_in(page, kva);
	
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
	int page_num = file_page->page_num;
	int page_num_written = 0;

	for (int i = 0; i<page_num; i++)
	{
		int read_byte = file_read_at(file_page->file, page->frame->kva, 4096, file_page->offset);
		if (read_byte == PGSIZE)
		{
			page = spt_find_page(&thread_current()->spt, page->va + PGSIZE);
			file_page = &page->file;
		}
		else
		{
			for (char *start = page->frame->kva + read_byte; start < page->frame->kva + PGSIZE; start++)
			{
				*start = 0;
			}
			page_num_written = i+1;

			page = spt_find_page(&thread_current()->spt, page->va + PGSIZE);
			file_page = &page->file;
			break;
		}
	}

	while (page_num_written < page_num)
	{
		for (char *start = page->frame->kva; start < page->frame->kva + PGSIZE; start++)
		{
			*start = 0;
		}
		page_num_written++;

		page = spt_find_page(&thread_current()->spt, page->va + PGSIZE);
		file_page = &page->file;

	}

	return true;

}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
	if (!page->written) return false;
	else
	{
		int page_num = file_page->page_num;
		for (int i = 0; i<page_num; i++)
		{
			file_write_at(file_page->file, page->frame->kva, PGSIZE, file_page->offset);
			page = spt_find_page(&thread_current()->spt, page->va + PGSIZE);
			file_page = &page->file;
		}
		page->written = false;
		return true;
	}
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;

	file_backed_swap_out(page);
	file_close(page->file.file);

	int ref_cnt = page->frame->ref_cnt;
	if (ref_cnt == 1 ) palloc_free_page(page->frame);
	else page->frame->ref_cnt--;

}

void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
	if (addr == NULL || length == 0 || pg_ofs(addr) != 0 || file ==file_length(file)==0) return NULL;

	int page_num = (length%PGSIZE == 0)? length / PGSIZE : length/PGSIZE  + 1;

	// check if there is an overlap, if so return NULL(fail)
	for (int i = 0; i < page_num; i++)
	{
		if (spt_find_page(&thread_current()->spt, addr + i*PGSIZE) != NULL) return NULL;
	}

	for (int i = 0; i< page_num; i++)
	{
		vm_alloc_page_with_initializer(VM_FILE, addr + i*PGSIZE, writable, NULL, NULL);
		struct page *p = spt_find_page(&thread_current()->spt, addr + i*PGSIZE);
		
		
		if (i == 0) 
		{
			struct mmap_info *aux = malloc(sizeof(struct mmap_info));
			aux->file = file;
			aux->offset = offset;
			aux->mmap = true;
			aux->munmap = false;
			aux->page_num = page_num;

			p->uninit.aux = aux;
			
		}
		else
		{
			struct mmap_info *aux = malloc(sizeof(struct mmap_info));
			aux->file = file;
			aux->offset = offset + i*PGSIZE;
			aux->mmap = false;
			aux->munmap = false;
			aux->page_num = page_num;

			p->uninit.aux = aux;
		}
		
	}



}

/* Do the munmap */
void
do_munmap (void *addr) {
	struct page *p = spt_find_page(&thread_current()->spt, addr);
	

	if (p->file.mmap && !p->file.munmap)
	{
		int page_num = p->file.page_num;
		for(int i= 0; i<page_num; i++)
		{
			p = spt_find_page(&thread_current()->spt, addr + i*PGSIZE);
			
			file_backed_swap_out(p);
			
			spt_remove_page(&thread_current()->spt, p);
		}
	}
	else 
	{
		return;
	}
}
