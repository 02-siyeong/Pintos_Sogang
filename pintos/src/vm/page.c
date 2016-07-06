#include <debug.h>
#include <stddef.h>
#include "threads/malloc.h"
#include "vm/page.h"
#include "vm/frame.h"

static unsigned 
page_hash (const struct hash_elem *e, void *aux UNUSED)
{
	const struct page *p = hash_entry(e, struct page, hash_elem);
	return hash_bytes( &p->upage, sizeof (p->upage));
}

static bool 
page_less (const struct hash_elem *eA, const struct hash_elem *eB, void *aux UNUSED)
{
	const struct page *pA = hash_entry(eA, struct page, hash_elem);
	const struct page *pB = hash_entry(eB, struct page, hash_elem);
	return pA->upage < pB->upage;
}

struct page* 
page_lookup (struct page_table *pt, const void *address)
{
	struct hash *pages = &pt->pages; 
	struct page p;
	struct hash_elem *e;
	p.upage = address;
	e = hash_find (pages, &p.hash_elem);
	return e != NULL ? hash_entry(e, struct page, hash_elem) : NULL;
}

void 
page_init (struct page_table *pt)
{
	hash_init (&pt->pages, page_hash, page_less, NULL);
}

void 
page_insert (struct page_table *pt, void *upage, void *kpage, bool writable)
{
	struct page *p;
	p=calloc(1,sizeof(struct page));
	p->upage = upage;
	p->kpage = kpage;
	p->writable = writable;
	p->is_swapped = false;
	hash_insert (&pt->pages, &p->hash_elem);
}

static void 
page_destructor (struct hash_elem *e, void *aux UNUSED)
{
	struct page *p;

	p = hash_entry(e, struct page, hash_elem);
	if(p->is_swapped)
		swap_delete(p->sector_num);

	else
		frame_delete(p->kpage);
	free(p);
}

void 
page_remove(struct page_table *pt)
{
	hash_destroy (&pt->pages, page_destructor);
}

void 
page_swap(struct page_table *pt, void *upage,  size_t sector_num)
{
	struct page *p = page_lookup(pt, upage);
	p->sector_num = sector_num;
	p->is_swapped = true;
}
