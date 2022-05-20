/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/mmu.h"

// frame table implemented by doubly linked list
struct frame_table frame_table;


/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	list_init(&(frame_table.frame_list));
	frame_table.needle =list_tail(&frame_table.frame_list);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */

		/* TODO: Insert the page into the spt. */

		struct page *new_page = malloc(sizeof(struct page));
		void *initializer;
		if (VM_TYPE(type) == VM_ANON) initializer = anon_initializer;
		if (VM_TYPE(type) == VM_FILE) initializer = file_backed_initializer;

		uninit_new(new_page, upage, init, type, aux, initializer);
		new_page->writable = writable;
		new_page->type = VM_UNINIT;

		spt_insert_page(spt, new_page);

		return true;

	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function. */
	
	struct page temp;
	temp.va = pg_round_down(va);

	struct hash_elem *elem = hash_find(spt->spt_table, &(temp.hash_elem));
	if (elem == NULL) return NULL;
	else
	{
		page = hash_entry(elem, struct page, hash_elem);
		return page;
	}

}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;
	/* TODO: Fill this function. */
	if (hash_insert(spt->spt_table, &page->hash_elem) == NULL) succ = true;
	return succ;
	
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	hash_delete((thread_current()->spt.spt_table), &page->hash_elem);
	vm_dealloc_page (page);
	return true;
}


/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */
	struct list_elem *needle = frame_table.needle;
	struct list *frame_list = &(frame_table.frame_list);

	struct list_elem *curr = needle;
	while(true)
	{
		struct frame *f = list_entry(curr, struct frame, elem);
		if (pml4_is_accessed(thread_current()->pml4,f->page->va))
		{
			pml4_set_accessed(thread_current()->pml4, f->page->va, false);
			if(list_next(curr) == list_tail(frame_list))
			{
				curr = list_begin(frame_list);
			}
			else
			{
				curr = list_next(curr);
			}
		}
		else
		{
			pml4_set_accessed(thread_current()->pml4, f->page->va, true);
			needle = curr;
			break;
		}
	}
	victim = list_entry(needle, struct frame, elem);

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	if (pml4_is_dirty(&thread_current()->pml4, victim->page->va)) victim->page->written = true;

	// eliminate entry from page table
	pml4_clear_page(&thread_current()->pml4, victim->page);

	// swap_out
	swap_out(victim->page);

	// unlink existed pair between page and frame
	victim->page->frame = NULL;
	victim->page = NULL;

	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = malloc(sizeof(struct frame));
	/* TODO: Fill this function. */
	frame->kva = palloc_get_page(PAL_USER);
	frame->page = NULL;
	if (frame->kva == NULL) 
	{
		free(frame);
		frame = vm_evict_frame();
	} 
	else	// allocation success, need to push frame to frame table
	{
		frame->ref_cnt = 1;
		list_insert(frame_table.needle, &frame->elem);
	}
	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
	void *page = pg_round_down(addr);
	vm_alloc_page_with_initializer(VM_ANON, page, true, NULL, NULL);
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = spt_find_page(spt, addr);
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	bool valid = true;
	void *user_rsp = thread_current()->save_rsp;

	if (page == NULL) 
	{
		if (user_rsp < addr && addr < USER_STACK)
		{
			unsigned long check_max = addr;
			if (USER_STACK - check_max < (1<<20)) vm_stack_growth(addr);
		}
		else valid = false;
	}
	if (user && is_kernel_vaddr(page->va)) valid = false;
	if (write && !page->writable) valid = false;

	if (!valid)
	{
		// process exit & resource free
		supplemental_page_table_kill(spt);
		thread_exit();
	}
	
	return vm_do_claim_page (page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function */

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	pml4_set_page(thread_current()->pml4, page, frame->kva, page->writable);

	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	spt->spt_table = malloc(sizeof(struct hash));
	hash_init(spt->spt_table, page_hash, page_less, NULL);
}


bool claim_page(struct page *child_page, void *aux)
{
	struct page *parent_page = aux;
	struct hash_elem elem = child_page->hash_elem;

	memcpy(child_page, parent_page, sizeof(struct page));

	child_page->hash_elem = elem;

	parent_page->frame->ref_cnt++;
}


/* Copy supplemental page table from src to dst */
void alloc_page(struct hash_elem *e, void *aux)
{
	struct supplemental_page_table *dst = aux;

	struct page *parent_page = hash_entry(e, struct page, hash_elem);
	struct page *child_page = malloc(sizeof(struct page));

	// copy contents
	
	
	void *initializer;
	if (VM_TYPE(parent_page->type) == VM_ANON) initializer = anon_initializer;
	if (VM_TYPE(parent_page->type) == VM_FILE) initializer = file_backed_initializer;

	uninit_new(child_page, parent_page->va, claim_page ,parent_page->type, parent_page ,initializer);

	// insert
	hash_insert(dst->spt_table, &child_page->hash_elem);

}

bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
	(*src->spt_table).aux = dst;
	hash_apply(src->spt_table, alloc_page);
}


void delete_hash_destroy_page(struct hash_elem *e, void *aux)
{
	struct supplemental_page_table *spt = &thread_current()->spt;
	struct page *page = hash_entry(e, struct page, hash_elem);

	hash_delete(spt->spt_table, e);
	destroy(page);
}

/* swap out a page in spt */
void swap_out_spt(struct hash_elem *e, void *aux)
{
	struct supplemental_page_table *spt = &thread_current()->spt;
	struct page *page = hash_entry(e, struct page, hash_elem);
	swap_out(page);
}
/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	hash_apply(spt->spt_table, swap_out_spt);
	hash_apply(spt->spt_table, delete_hash_destroy_page);
	free(spt->spt_table);
}


unsigned page_hash(const struct hash_elem *p, void *aux UNUSED)
{
	const struct page *page = hash_entry (p, struct page, hash_elem);
  	return hash_bytes (&page->va, sizeof page->va);
}

bool page_less (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
	const struct page *pa = hash_entry (a, struct page, hash_elem);
  	const struct page *pb = hash_entry (b, struct page, hash_elem);

  	return pa->va < pb->va;
}