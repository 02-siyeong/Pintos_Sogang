#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/synch.h"
#include "threads/thread.h"

extern struct frametable ft;

struct frametable
	{
		struct frame *frames;
		size_t start;
		size_t end;
		size_t pin;
		
		struct lock frame_lock;
	};

struct frame
	{
		void *upage;
		struct thread *t;
	};

void frame_init (size_t ram_pages);
void frame_insert (struct thread *t, void *upage, void *kpage);
void frame_delete (void *kpage);
struct frame * frame_victim(void);

#endif
