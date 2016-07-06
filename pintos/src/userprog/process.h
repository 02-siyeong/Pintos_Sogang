#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "filesys/directory.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

extern struct lock filesys_lock;

struct process_status
	{
		struct lock wait_lock;
		struct condition wait_cond;

		tid_t pid;
		bool is_terminated;	
		bool is_done_parent;
		int return_status;
	
		struct list_elem elem;

		struct thread* parent;
		struct thread* child;
		char *fn_copy; 
		
		bool success;
	};

struct file_description
	{
		int fd;
		struct file *file;
		struct list_elem elem;
	};

#endif /* userprog/process.h */
