#ifndef VM_ANON_H
#define VM_ANON_H
#include "vm/vm.h"
#include "devices/disk.h"
struct page;
enum vm_type;

struct anon_page {
    // a page data occupies 8 sectors when swapped out
    // saved_sector_start is the start sector number
    disk_sector_t saved_sector_start;
    bool is_swapped_out;
};

void vm_anon_init (void);
bool anon_initializer (struct page *page, enum vm_type type, void *kva);

#endif
