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
	file_page->bytes_to_read = aux->read_bytes;
	
	
	file_backed_swap_in(page, kva);
	
	return true;
	
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page  = &page->file;

	int read_byte = file_read_at(file_page->file, kva, file_page->bytes_to_read, file_page->offset);
	int zero_byte = PGSIZE - read_byte;
	
	if (zero_byte != 0 )
	{
		
		memset(kva + read_byte, 0, zero_byte);
		
	}
	
	return true;

}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
	int page_write = file_page->bytes_to_read;
	
	if (pml4_get_page(thread_current()->pml4, page->va))
	{
		if (pml4_is_dirty(thread_current()->pml4, page->va))
		{
			file_write_at(file_page->file, page->frame->kva, page_write, file_page->offset);
			pml4_set_dirty(thread_current()->pml4, page->va, false);
			return true;
		}
		else return true;
	}
	else
	{
		if (!page->written) return true;
		file_write_at(file_page->file, page->frame->kva, page_write, file_page->offset);
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
	
}

void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
	if (addr == NULL || length == 0 || pg_ofs(addr) != 0 || file_length(file)==0 || offset % PGSIZE != 0) return NULL;
	if (is_kernel_vaddr(addr)) return NULL;
	if (is_kernel_vaddr(addr + length)) return NULL;
	if (addr > addr + length) return NULL;
	

	int page_num = (length % PGSIZE == 0)? length / PGSIZE : length / PGSIZE  + 1;
	
	// check overlap
	for (int i = 0; i < page_num; i++)
	{
		if (spt_find_page(&thread_current()->spt, addr + i*PGSIZE) != NULL) return NULL;
	}
	
	// allocate uninit pages
	for (int i = 0; i < page_num; i++)
	{
		size_t page_read_bytes = length < PGSIZE ? length : PGSIZE;
		struct mmap_info *aux = malloc(sizeof(struct mmap_info));
		if (aux == NULL) return NULL;
		
		// env for initial page which is used for munmap
		struct file *reopen = file_reopen(file);
		if (reopen != NULL) aux->file = reopen;
		else return NULL;

		aux->offset = offset + i * PGSIZE;

		if (i == 0) aux->mmap = true;
		else aux->mmap = false;

		aux->munmap = false;
		aux->page_num = page_num;
		aux->read_bytes = page_read_bytes;

		if (!vm_alloc_page_with_initializer(VM_FILE, addr + i*PGSIZE, writable, NULL, aux)) return NULL;
		

		
		length -= page_read_bytes;
		
	}
	
	return addr;

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
			spt_remove_page(&thread_current()->spt, p);
			
		}
		
	}
	
	return;
	
}
