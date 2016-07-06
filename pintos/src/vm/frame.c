#include "vm/frame.h"
#include <hash.h>
#include "threads/pte.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"

struct frametable ft;

void 
frame_init (size_t ram_pages)
{
	size_t i;
	size_t page_num;
	void * last_frame;
	if (ram_pages * sizeof(struct frame) % PGSIZE)
		page_num = ram_pages * sizeof(struct frame) / PGSIZE; 
	else
		page_num = ram_pages * sizeof(struct frame) / PGSIZE - 1; 
 
	lock_init (&ft.frame_lock);
	ft.frames = palloc_get_page (PAL_USER | PAL_ZERO);
	
	ft.end = ram_pages;

	last_frame = ft.frames;
	for (i = 0; i < page_num; i++) 
		last_frame = palloc_get_page(PAL_USER | PAL_ZERO | PAL_ASSERT);
	
	ft.start = ((unsigned int)(last_frame - PHYS_BASE) >> 12) + 1;
	ft.pin = ft.start;
}

void
frame_insert (struct thread *t, void *upage, void *kpage)
{
	struct frame * f = &ft.frames[(unsigned int)(kpage - PHYS_BASE) >> 12];
	
	f->t = t;
	f->upage = upage;
}

void 
frame_delete (void *kpage)
{
	struct frame * f = &ft.frames[(unsigned int)(kpage - PHYS_BASE) >> 12];
	f->t = NULL;
	f->upage = NULL;
}

struct frame *
frame_victim (void)
{
	size_t i;
	struct frame * victim = NULL;
	
	for (i = ft.pin; i<ft.end; i++)
		{
			struct frame * f;
			f = &ft.frames[i];
			if (pagedir_is_accessed ((f->t)->pagedir,f->upage) 
					|| pagedir_is_accessed (f->t->pagedir, pagedir_get_page (f->t->pagedir,f->upage)))
				{
					pagedir_set_accessed ((f->t)->pagedir,f->upage, 0);
					pagedir_set_accessed (f->t->pagedir,pagedir_get_page (f->t->pagedir,f->upage), 0);
				}
			
			else
				{
					victim = f;
					ft.pin = i + 1;
					break;
				}
		}

	if (victim == NULL)
		{
			ft.pin = ft.start;
			victim = frame_victim ();
		}

	return victim;
}
