#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "devices/block.h"

struct page_table
	{
		struct hash pages;
	};

struct page
	{
		struct hash_elem hash_elem;
		void *upage;
		void *kpage;
		size_t sector_num;
		bool is_swapped;
		bool writable;
	};

void page_init (struct page_table *pt);
void page_insert (struct page_table *pt, void *upage, void *kpage, bool writable);
struct page* page_lookup (struct page_table * pt, const void *address);
void page_remove (struct page_table *pt);
void page_swap (struct page_table *pt, void *upage,  size_t sector_num);

#endif
