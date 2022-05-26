/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/mmu.h"
#include "userprog/syscall.h"
#include "vm/file.h"

// frame table implemented by doubly linked list
struct frame_table frame_table;

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void vm_init(void)
{
	vm_anon_init();
	vm_file_init();
#ifdef EFILESYS /* For project 4 */
	pagecache_init();
#endif
	register_inspect_intr();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	list_init(&(frame_table.frame_list));
	frame_table.needle = list_tail(&frame_table.frame_list);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type(struct page *page)
{
	int ty = VM_TYPE(page->operations->type);
	switch (ty)
	{
	case VM_UNINIT:
		return VM_TYPE(page->uninit.type);
	default:
		return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim(void);
static bool vm_do_claim_page(struct page *page);
static struct frame *vm_evict_frame(void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable,
									vm_initializer *init, void *aux)
{

	ASSERT(VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page(spt, upage) == NULL)
	{
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */

		/* TODO: Insert the page into the spt. */

		struct page *new_page = malloc(sizeof(struct page));
		void *initializer;
		if (VM_TYPE(type) == VM_ANON)
			initializer = anon_initializer;
		if (VM_TYPE(type) == VM_FILE)
			initializer = file_backed_initializer;

		uninit_new(new_page, upage, init, type, aux, initializer);
		new_page->writable = writable;

		spt_insert_page(spt, new_page);

		return true;
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page(struct supplemental_page_table *spt UNUSED, void *va UNUSED)
{

	struct page temp;
	temp.va = pg_round_down(va);
	if (hash_empty(&spt->spt_table))
		return NULL;
	struct hash_elem *elem = hash_find(&spt->spt_table, &(temp.hash_elem));
	if (elem == NULL)
		return NULL;
	else
	{
		return hash_entry(elem, struct page, hash_elem);
	}
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt UNUSED,
					 struct page *page UNUSED)
{
	int succ = false;
	/* TODO: Fill this function. */

	if (hash_insert(&spt->spt_table, &page->hash_elem) == NULL)
		succ = true;
	return succ;
}

void spt_remove_page(struct supplemental_page_table *spt, struct page *page)
{
	hash_delete((&spt->spt_table), &page->hash_elem);
	vm_dealloc_page(page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim(void)
{
	struct frame *victim = NULL;
	/* TODO: The policy for eviction is up to you. */
	struct list_elem *needle = frame_table.needle;
	struct list *frame_list = &(frame_table.frame_list);

	struct list_elem *curr = needle;
	if (curr == list_tail(frame_list))
		curr = list_begin(frame_list);
	while (true)
	{
		struct frame *f = list_entry(curr, struct frame, elem);
		if (pml4_is_accessed(thread_current()->pml4, f->page->va))
		{
			pml4_set_accessed(thread_current()->pml4, f->page->va, false);
			if (list_next(curr) == list_tail(frame_list))
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
vm_evict_frame(void)
{
	struct frame *victim UNUSED = vm_get_victim();
	/* TODO: swap out the victim and return the evicted frame. */

	if (pml4_is_dirty(&thread_current()->pml4, victim->page->va))
		victim->page->written = true;

	// eliminate entry from page table
	pml4_clear_page(&thread_current()->pml4, victim->page->va);

	enum vm_type type = victim->page->operations->type;
	// swap_out
	if (VM_TYPE(type) == VM_ANON || VM_TYPE(type) == VM_FILE)
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
vm_get_frame(void)
{
	struct frame *frame = malloc(sizeof(struct frame));
	/* TODO: Fill this function. */
	frame->kva = palloc_get_page(PAL_USER);
	frame->page = NULL;
	if (frame->kva == NULL)
	{
		free(frame);
		frame = vm_evict_frame();
	}
	else // allocation success, need to push frame to frame table
	{
		// frame->ref_cnt = 1;
		list_insert(frame_table.needle, &frame->elem);
	}
	ASSERT(frame != NULL);
	ASSERT(frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth(void *addr UNUSED)
{
	void *page = pg_round_down(addr);
	vm_alloc_page_with_initializer(VM_ANON | VM_MARKER_0, page, true, NULL, NULL);
	vm_claim_page(page);
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp(struct page *page UNUSED)
{
}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f UNUSED, void *addr UNUSED,
						 bool user UNUSED, bool write UNUSED, bool not_present UNUSED)
{
	struct supplemental_page_table *spt UNUSED = &thread_current()->spt;
	struct page *page = spt_find_page(spt, addr);
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */

	if (user)
		thread_current()->save_rsp = f->rsp;
	void *user_rsp = thread_current()->save_rsp;

	if (addr == NULL)
		exit(-1);
	if (is_kernel_vaddr(addr))
		exit(-2);

	if (page == NULL)
	{
		if (user_rsp - 50 <= addr && (uint64_t)addr <= USER_STACK)
		{
			if (USER_STACK - (uint64_t)addr < (1 << 20))
			{
				vm_stack_growth(addr);
				return true;
			}
			exit(-3);
		}
		else
		{
			exit(-4);
		}
	}

	if (write && !(page->writable))
	{
		exit(-5);
	}

	return vm_do_claim_page(page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page)
{
	destroy(page);
	free(page);
}

/* Claim the page that allocate on VA. */
bool vm_claim_page(void *va UNUSED)
{
	struct page *page = spt_find_page(&thread_current()->spt, va);
	/* TODO: Fill this function */

	return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page(struct page *page)
{
	struct frame *frame = vm_get_frame();
	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	if (pml4_get_page(thread_current()->pml4, page->va) == NULL)
	{
		if (!pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->writable))
			return false;
	}

	return swap_in(page, frame->kva);
}

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt UNUSED)
{
	hash_init(&spt->spt_table, page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */
void copy_spt(struct hash_elem *e, void *aux)
{
	struct supplemental_page_table *dst = aux;

	struct page *parent_page = hash_entry(e, struct page, hash_elem);
	enum vm_type p_type = parent_page->operations->type;
	bool wr = parent_page->writable;
	void *p_va = parent_page->va;
	vm_initializer *init = parent_page->uninit.init;

	if (VM_TYPE(p_type) == VM_UNINIT)
	{

		void *aux = parent_page->uninit.aux;
		vm_alloc_page_with_initializer(parent_page->uninit.type, p_va, wr, init, aux);
	}
	else
	{
		if (VM_TYPE(p_type) == VM_ANON)
		{
			vm_alloc_page(p_type, p_va, wr);
			struct page *child_page = spt_find_page(dst, p_va);
			vm_do_claim_page(child_page);
			memcpy(&child_page->anon, &parent_page->anon, sizeof(struct anon_page));
			memcpy(child_page->frame->kva, parent_page->frame->kva, PGSIZE);
		}
		else
		{
			struct mmap_info *aux_child = malloc(sizeof(struct mmap_info));
			aux_child->file = file_reopen(parent_page->file.file);
			aux_child->offset = parent_page->file.offset;
			aux_child->mmap = parent_page->file.mmap;
			aux_child->munmap = parent_page->file.munmap;
			aux_child->page_num = parent_page->file.page_num;
			aux_child->read_bytes = parent_page->file.bytes_to_read;

			vm_alloc_page_with_initializer(p_type, p_va, wr, NULL, aux_child);
			struct page *child_page = spt_find_page(dst, p_va);
			vm_do_claim_page(child_page);
			free(aux_child);
			// memcpy(child_page->frame->kva, parent_page->frame->kva, PGSIZE);
		}
	}
}

bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED,
								  struct supplemental_page_table *src UNUSED)
{
	(src->spt_table).aux = dst;
	hash_apply(&src->spt_table, copy_spt);

	return true;
}

void destroy_page(struct hash_elem *e, void *aux)
{
	struct page *page = hash_entry(e, struct page, hash_elem);

	destroy(page);
}

/* swap out a page in spt */
void swap_out_and_destroy(struct hash_elem *e, void *aux)
{
	if (e != NULL)
	{

		struct page *page = hash_entry(e, struct page, hash_elem);
		enum vm_type type = page->operations->type;

		if (VM_TYPE(type) == VM_ANON || VM_TYPE(type) == VM_FILE)
			swap_out(page);

		vm_dealloc_page(page);
	}
}
/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED)
{
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */

	// write back for each elements in hashtable
	// if(!hash_empty(&spt->spt_table)) hash_apply(&spt->spt_table, swap_out_and_destroy);

	hash_clear(&spt->spt_table, swap_out_and_destroy);
}

unsigned page_hash(const struct hash_elem *p, void *aux UNUSED)
{
	const struct page *page = hash_entry(p, struct page, hash_elem);
	return hash_bytes(&page->va, sizeof page->va);
}

bool page_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
	const struct page *pa = hash_entry(a, struct page, hash_elem);
	const struct page *pb = hash_entry(b, struct page, hash_elem);

	return pa->va < pb->va;
}
