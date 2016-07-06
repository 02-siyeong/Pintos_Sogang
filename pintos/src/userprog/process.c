#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

/* User Additional Library. */
#include "userprog/syscall.h"
#include "threads/malloc.h"
#include "threads/synch.h"

#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;
  
	/* Make a copy of FILE_NAME.
	   Otherwise there's a race between the caller and load(). */
	
	struct thread * t = thread_current ();

	//printf("[execute][name] %s, %x\n", thread_name(), t);

	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
	{
			return TID_ERROR;
	}
	
	strlcpy (fn_copy, file_name, PGSIZE);

  /* User Additional Code */
  char *open_file_name, *thread_name, *bp;

	open_file_name =  palloc_get_page(0);
	if (open_file_name  == NULL)
		{
			palloc_free_page (fn_copy);
			return TID_ERROR;
		}
	
	struct process_status *child = malloc(sizeof(struct process_status));
	if (child == NULL)
		{
			palloc_free_page (fn_copy);
			palloc_free_page (open_file_name);
			return TID_ERROR;				
		}

	strlcpy(open_file_name, file_name, PGSIZE);
  thread_name = strtok_r (open_file_name, " ", &bp);

	lock_init (&child->wait_lock);
	cond_init (&child->wait_cond);
	child->pid = -2;
	child->is_done_parent = false;
	child->is_terminated = false;
	child->return_status = -1;
	child->parent = t;
	child->fn_copy = fn_copy;

  tid = thread_create (thread_name, PRI_DEFAULT, start_process, child);
	palloc_free_page (open_file_name);

	if (tid == TID_ERROR)
		{
			palloc_free_page (fn_copy);
			free (child);
			return TID_ERROR;
		}

	intr_disable();
	thread_block();
	intr_enable();
	thread_unblock(child->child);	
	//lock_acquire(&child->wait_lock);

	/*
	if (child->pid == -2)
		{
			cond_wait(&child->wait_cond, &child->wait_lock);
		}
	*/
	if (child->pid >= 0)
		list_push_back (&t->child_list, &child->elem);
	
	if (child->pid == -1)
		{
			thread_yield();
			free (child);
			return TID_ERROR;
		}

	return child->pid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
	struct process_status *status = file_name_;
  char *file_name = status->fn_copy;
  struct intr_frame if_;
  bool success;

	//printf("[start][name] %s\n", thread_name());
	/* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  
  success = load (file_name, &if_.eip, &if_.esp);

	palloc_free_page (file_name);
		
	//printf("1");  
	status->child = thread_current ();
	thread_current ()->process_status = status;

  //lock_acquire(&status->wait_lock);
	if (!success)
		status->pid = -1;
	else
		status->pid = thread_current()->tid;

	//printf("2");
	thread_unblock (status->parent);
	intr_disable();
	thread_block();
	intr_enable();
	//cond_signal(&status->wait_cond, &status->wait_lock);
	//lock_release(&status->wait_lock);
	
	//thread_unblock (status->parent);

	if (!success) {
		thread_exit ();
	}
   /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */

int
process_wait (tid_t child_tid UNUSED) 
{
	struct thread *t = thread_current ();
	bool found = false;
	struct process_status* kid = NULL;
	struct list_elem *e = NULL;

	//printf("[wait][name]: %s, [num]: %d\n", thread_name(),j++);
	if (!list_empty(&t->child_list))
		{
			for (e = list_begin(&t->child_list); e != list_end (&t->child_list); e = list_next(e))
				{
					kid = list_entry(e, struct process_status, elem);
					if (kid->pid == child_tid)
						{
							found = true;
							break;				
						}				
				}
		}

	if (!found) return -1;
	 
	list_remove (e);
	
	//printf("[wait]나만  %s\n", thread_name());
	lock_acquire(&kid->wait_lock);
	//sema_down(&kid->lock);

	if (!kid->is_terminated)
		{
			//sema_up (&kid->lock);
			//printf("[termin] 나 잔다 %s\n", thread_name());
			cond_wait(&kid->wait_cond,&kid->wait_lock);
			//printf("[termin]나 깼다%s\n", thread_name());
		}

	int ret = kid->return_status; 
	if (!kid) free (kid);
	return ret;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */

	/* User additional Code */

	lock_acquire(&filesys_lock);
	while (!list_empty (&cur->fd_list))
		{
			struct list_elem *e = list_pop_back (&cur->fd_list);
			struct file_description *found = NULL;
			
			found = list_entry (e, struct file_description, elem);
			file_close (found->file);
			free (found);//palloc_free_page (found);				
		}
	lock_release(&filesys_lock);

	//printf("[exit][name]: %s, [num]: %d\n", thread_name(),i++);
	if (!list_empty(&cur->child_list))
		{
			struct list_elem *e;
			struct process_status *kid;

			for (e = list_begin (&cur->child_list); e != list_end(&cur->child_list);) 
				{ 
					kid = list_entry(e, struct process_status, elem); 
				
					if (kid->is_terminated)
						{ 
							e = list_remove(e); 
							free (kid); //palloc_free_page(kid); 
						} 
				
					else
						{
							//printf("[exit]나만  %s\n", thread_name());
							lock_acquire (&kid->wait_lock);
							kid->is_done_parent = true; 
							//printf("[exit]나만 end %s\n", thread_name());
							lock_release (&kid->wait_lock);
							//sema_up (&kid->lock);
							e = list_next(e); 
						} 
				}
		} 
	
		//printf("[exit][name]: %s, [num]: %d, child:%d\n", thread_name(),i++, list_empty(&cur->child_list));		
		if (cur->process_status)
			{ 
				//////sema_down (&cur->process_status->lock);
				//printf("[exit2]나만  %s\n", thread_name());				
				lock_acquire (&cur->process_status->wait_lock);
				cur->process_status->is_terminated = true; 

				//sema_up (&cur->process_status->lock);

				//printf("일어나아빠  %s\n", thread_name());
				//if (cur->process_status->parent->status == THREAD_BLOCKED)
				cond_signal (&cur->process_status->wait_cond, &cur->process_status->wait_lock);
					
				//printf("%s, %d\n", thread_name(), cur->process_status->is_done_parent);
				if(cur->process_status->is_done_parent){
					free (cur->process_status); 
				}
				else {
				  //sema_up (&cur->process_status->lock);
					lock_release(&(cur->process_status->wait_lock)); 
					//printf("[exit2]나만  end %s\n", thread_name());
				}
			}

	page_remove (&cur->pt);
	pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
t
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */

#define MAX_ARG_NUM 64
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofset;
  bool success = false;
  int i;
 
  char	*fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
			return TID_ERROR;			

  int arg_stack_size = 0;
  char *entry, * bp;
  char *arg_stack[ MAX_ARG_NUM ];
  void* esp_first;
  /* End of Added variables */ 

	lock_acquire (&filesys_lock);
  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

	page_init (&t->pt); //Project #4.
  
	/* User Additional Code - Project1. */
	strlcpy (fn_copy, file_name, PGSIZE);
  entry = strtok_r (fn_copy, " ", &bp);
	arg_stack[0] =  malloc (sizeof (char) * (strlen (entry) + 1));
	if (!arg_stack[0]) goto done;//
	
	strlcpy (arg_stack[0], entry, strlen (entry) + 1);
	
	if( !entry ) goto done;
 
 	//lock_acquire (&filesys_lock); 
	/* Open executable file. */
  //printf("%s\n", arg_stack[0]);
	file = filesys_open (arg_stack[0]);
	
	if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }
  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }
  /* Read program headers. */
  file_ofset = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofset < 0 || file_ofset > file_length (file))
        goto done;
      file_seek (file, file_ofset);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofset += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (mem_page == 0) mem_page = 0x1000;
							if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }
  
	/* Set up stack. */
  if (!setup_stack (esp))
    goto done;

	/* User Additional code. */
	esp_first = *esp;
	
	while (entry)
		{
			entry = strtok_r (NULL, " ", &bp);
			if(entry){ 
				arg_stack[++arg_stack_size] = malloc(sizeof (char) * (strlen (entry) + 1));
				if (!arg_stack[arg_stack_size-1]) goto done; ///
				strlcpy(arg_stack[arg_stack_size], entry, strlen (entry) + 1);
			}
 		}

	for(i = arg_stack_size; i >= 0 ; i--)
		{
			*esp -= strlen (arg_stack[i]) + 1;
			strlcpy(*esp, arg_stack[i], strlen(arg_stack[i]) + 1);
		}
	
	//Word alignment
 	while((int)(*esp) % 4 != 0)	*esp -= 1;
	*esp -= 4; *(void **)(*esp) = NULL;

	for(i = arg_stack_size; i >= 0; i--)
		{
			*esp -= 4;
			*(int*)(*esp) = ( int )esp_first - strlen( arg_stack[i] ) - 1  ;
			esp_first -= strlen( arg_stack[i] ) + 1 ;
		}

	*esp -= 4;		*(char **)(*esp) = *esp + 4;
	*esp -= 4;		*(int *)(*esp) = arg_stack_size + 1;
	*esp -= 4;		*(void **)(*esp) = NULL;
	
	*eip = (void (*) (void)) ehdr.e_entry;

	success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  lock_release(&filesys_lock);
	//printf("여기 %s\n", arg_stack[0]);

	palloc_free_page (fn_copy);	
	for (i = arg_stack_size; i >= 0; i--)
		free (arg_stack[i]);
	
	file_close (file);  
	return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */

static void *
page_alloc (uint8_t *upage)
{
	uint8_t *kpage;
	kpage = palloc_get_page(PAL_USER|PAL_ZERO);

	if (kpage == NULL)
		{
			struct frame * victim;
			uint8_t *victim_page;
			size_t sector;
			
			lock_acquire(&(ft.frame_lock));	
			victim = frame_victim();

			victim_page = pagedir_get_page(victim->t->pagedir, victim->upage);
			sector = swap_insert(victim_page);
			pagedir_clear_page(victim->t->pagedir, victim->upage);	
			page_swap(&victim->t->pt, victim->upage, sector); 
			frame_delete(victim_page);
			palloc_free_page(victim_page);
			kpage = palloc_get_page(PAL_USER|PAL_ZERO);
			lock_release(&(ft.frame_lock));
			ASSERT (kpage != NULL);
		}
  	
		frame_insert(thread_current(), upage, kpage);
	return kpage;
}

static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *knpage = page_alloc (upage);

      /* Load this page. */
      if (file_read (file, knpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (knpage);
          return false; 
        }
      memset (knpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, knpage, writable)) 
        {
          frame_delete (knpage);
					return false; 
        }

			page_insert(&thread_current()->pt, upage, knpage, writable);

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = page_alloc (((uint8_t *) PHYS_BASE) - PGSIZE);
 	
	success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
  
	if (success)
    {    
			page_insert (&thread_current ()->pt, ((uint8_t*) PHYS_BASE) - PGSIZE, kpage, true);
			*esp = PHYS_BASE;
		}
  else
		{
				frame_delete (kpage);
        palloc_free_page (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *th = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (th->pagedir, upage) == NULL
          && pagedir_set_page (th->pagedir, upage, kpage, writable));
}
