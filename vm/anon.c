/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"

struct swap_table swap_table;

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	swap_disk = disk_get(1,1);
	// each bit represent a pagesize(4096) data & size of sector is 512
	// each bit in bitmap represent 8 disk sectors
	swap_table.table = bitmap_create(disk_size(swap_disk)/8);
	bitmap_set_all(swap_table.table, false);
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;
	anon_page->saved_sector_start = 0;

	// this function is called at first fault, so data is not swapped out
	anon_page->is_swapped_out = false;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;

	if (!anon_page->is_swapped_out) return false;
	else
	{
		for (int i = 0; i < 8; i++)
		{
			disk_read(swap_disk, anon_page->saved_sector_start + i, page->frame->kva + i * 512);
		}
		anon_page->is_swapped_out = false;
		return true;
	}
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	if (anon_page->is_swapped_out) return false;
	else{
		size_t free_slot_index = bitmap_scan_and_flip(swap_table.table, 0, 1, false);
		ASSERT(free_slot_index != BITMAP_ERROR); 

		disk_sector_t start_sector = 8*free_slot_index;
		
		for ( int i =0; i<8; i++)
		{
			disk_write(swap_disk, start_sector + i, page->frame->kva + i * 512);
		}

		anon_page -> saved_sector_start = start_sector;
		anon_page -> is_swapped_out = true;
	}

}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;

	if (anon_page->is_swapped_out)
	{
		// data stored in disk, need to clear disk sector(frame refcnt = 0)
		bitmap_set(swap_table.table, (anon_page->saved_sector_start)/8, false);
	}
	else
	{
		//data stored in frame, need to clear frame
		int ref_cnt = page->frame->ref_cnt;
		if (ref_cnt == 1 ) palloc_free_page(page->frame);
		else page->frame->ref_cnt--;
	}
}
