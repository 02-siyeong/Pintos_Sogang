#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

/* Additional Library. */
#include "lib/user/syscall.h"
#include "userprog/process.h"
#include "threads/synch.h"
#include "devices/input.h"
#include "lib/kernel/console.h"
//#include "lib/string.h"
#include "devices/shutdown.h"

#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/directory.h"
#include "threads/palloc.h"
//#include "threads/malloc.h"

#define GET_DIR 1
#define GET_FILE 2

static int get_user (const uint8_t *uaddr);
//static bool put_user (uint8_t *udst, uint8_t byte);
		 
bool is_possible_user_read (void *src, void *dest, int limit);
bool is_string(const char *src);

struct file* get_file_by_fd (int fd, int flag);

/* USER_PROJECT 1. */
int sys_fibonacci (int n);
int sys_sum_of_four_integers (int a, int b, int c, int d);

pid_t sys_exec (const char *cmd_line);
int sys_wait (pid_t pid);

bool sys_read (int fd, void *buffer, unsigned size, int *ret);
int sys_write (int fd, const void *buffer, unsigned size);

/* USER_PROJECT 2. */
bool sys_create (const char *file_name, unsigned intial_size, bool *ret);
bool sys_remove (const char *file_name, bool *ret);

bool sys_seek (int fd, unsigned position);
bool sys_close (int fd);

bool sys_tell (int fd, unsigned *ret);
int sys_filesize (int fd);
int sys_open (const char *file_name);

static void syscall_handler (struct intr_frame *);

//struct lock syscall_lock;

void
syscall_init (void) 
{
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
	//lock_init(&syscall_lock);
}

#define WORD 4

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
		//lock_acquire(&syscall_lock);
		int syscall_num;
		uint32_t *argument = f->esp;

		if(!is_possible_user_read(f->esp, &syscall_num, WORD)) goto FAIL;

		switch (syscall_num){
				case SYS_HALT:
					{
						//lock_release(&syscall_lock);
						sys_halt();
						break;
					}

				case SYS_EXIT:
					{

						int status;
						if(!is_user_vaddr(argument+3)) goto FAIL;
						if(!is_possible_user_read(argument+1, &status, WORD)) goto FAIL;
						
						//lock_release(&syscall_lock);
						sys_exit(status);
						break;
					
					}

				case SYS_WRITE:
					{
						int fd; const void* buffer = NULL; unsigned size = 0;
						if (!is_possible_user_read(argument+5, &fd, WORD)) goto FAIL;
						if (!is_possible_user_read(argument+6, &buffer, WORD)) goto FAIL;
						if (!is_possible_user_read(argument+7, &size, WORD)) goto FAIL;
						
						f->eax = sys_write(fd, buffer, size);
						break;
					
					}

				case SYS_READ:
					{
						int fd; void* buffer = NULL; unsigned size = 0; int ret = 0;
						if (!is_possible_user_read(argument+5, &fd, WORD)) goto FAIL;
						if (!is_possible_user_read(argument+6, &buffer, WORD)) goto FAIL;
						if (!is_possible_user_read(argument+7, &size, WORD)) goto FAIL;

						if (!sys_read (fd, buffer, size, &ret)) goto FAIL;
						f->eax = ret;
						break;
					}

				case SYS_EXEC:
					{
						const char* cmdline;		
	
						if (!is_possible_user_read(argument+1, &cmdline, WORD)) goto FAIL;
						//if (!is_possible_user_string(cmdline)) goto FAIL;
		
						//printf("%s\n",cmdline);
						f->eax = sys_exec (cmdline);
						break;	
					}

				case SYS_WAIT:
					{
						pid_t pid;
						if (!is_possible_user_read(argument+1, &pid, WORD)) goto FAIL;
						f->eax = sys_wait (pid);
						//f->eax = process_wait(pid);
						break;
					}
	
				case SYS_CREATE:
					{
						const char *file_name;
						unsigned initial_size;
						bool ret;

						if (!is_possible_user_read(argument+4, &file_name, WORD)) goto FAIL;
						if (!is_possible_user_read(argument+5, &initial_size, WORD)) goto FAIL;
					
						//printf("%s, %d\n", file_name, initial_size);
						if (!sys_create (file_name, initial_size, &ret)) goto FAIL;
						f->eax = ret;
						break;
					}

				case SYS_REMOVE:
					{
						const char *file_name;
						bool ret;

						if (!is_possible_user_read(argument+1, &file_name, WORD)) goto FAIL;

						if (!sys_remove (file_name, &ret)) goto FAIL;
						f->eax = ret;
						break;				
					}

				case SYS_OPEN:
					{
						const char *file_name;
						if (!is_possible_user_read(argument+1, &file_name, WORD)) goto FAIL;
						
						f->eax = sys_open (file_name);				
						break;
					}

				case SYS_CLOSE:
					{
						int fd;
						if (!is_possible_user_read(argument+1, &fd, WORD)) goto FAIL;
						
						if (!sys_close(fd)) goto FAIL;
						break;				
					}


				case SYS_FILESIZE:
					{
						int fd;
						if (!is_possible_user_read(argument+1, &fd, WORD)) goto FAIL;
						
						f->eax = sys_filesize (fd);
						break;				
					}

				case SYS_SEEK:
					{
						int fd;
						unsigned position;
						if (!is_possible_user_read(argument+4, &fd, WORD)) goto FAIL;
						if (!is_possible_user_read(argument+5, &position, WORD)) goto FAIL;
					
						if (!sys_seek (fd, position)) goto FAIL;
						break;
					}
				case SYS_TELL:
					{
						int fd;
						unsigned ret;
						if (!is_possible_user_read(argument+1, &fd, WORD)) goto FAIL;

						if (!sys_tell (fd, &ret)) goto FAIL;
						f->eax = ret;
						break;
					}

				case SYS_FIBONACCI:
					{
						int n;
						if (!is_possible_user_read(argument+1, &n, WORD)) goto FAIL;
						f->eax = sys_fibonacci (n);
						break;
					}
				case SYS_SUM_OF_FOUR_INTEGERS:
					{
						int a, b, c, d;
						if (!is_possible_user_read(argument+6, &a, WORD)) goto FAIL;
						if (!is_possible_user_read(argument+7, &b, WORD)) goto FAIL;
						if (!is_possible_user_read(argument+8, &c, WORD)) goto FAIL;
						if (!is_possible_user_read(argument+9, &d, WORD)) goto FAIL;
						f->eax = sys_sum_of_four_integers (a,b,c,d);
						break;
					}
				default:
					{
						goto FAIL;
					}
		}
	//lock_release(&syscall_lock);
	return;
FAIL:
	//lock_release(&syscall_lock);
	sys_exit(-1);
}

/* Pintos manual Reference */

/* Reads a byte at user virtual address UADDR.
	 UADDR  must be below PHYS_BASE.
	 Returns the byte value if successful, -1 if a segfault
	occurred. */
static int
get_user (const uint8_t *uaddr)
{
	if((void *)uaddr>=PHYS_BASE)
		return -1;	
	int result;
	asm ("movl $1f, %0; movzbl %1, %0; 1:"
			 : "=&a" (result) : "m" (*uaddr));
	return result;
}
/* Writes BYTE to user address UDST.
	UDST must be below PHYS_BASE.
	Returns true if successful, false if a segfault occurred. */


static bool
put_user (uint8_t *udst, uint8_t byte)
{
	int error_code;
	asm ("movl $1f, %0; movb %b2, %1; 1:"
			 : "=&a" (error_code), "=m" (*udst) : "q" (byte));
	return error_code != -1;
}

/* Memory check */
bool
is_possible_user_read (void *src, void* dest, int limit)
{
	int value, i ;

	for (i =0 ; i < limit; i++)
		{
			value = get_user(src+i);
			if (value == -1) return false;
			*(char*)(dest+i) = value&0xff;
		}
	return true;
}

bool
is_string (const char *src)
{
	int value, i;
	
	for (i = 0;;i++)
		{
			value = get_user ((void*)src+i);
			if (value == -1) return false;
			if (value == '\0') break;				
		}
	
	return true;
}

bool 
user_mem_check(const void *src, int bytes, bool writable) 
{ 
	int value, i; 
	
	for (i=0; i<bytes ; i++){ 
		value = get_user(src+i); 
     if(value==-1) 
     return false; 
	if(writable && !put_user(src+i, 0)) return false; 
	} 
	return true; 
} 


/* System call imp. */
void
sys_halt (void)
{
	shutdown_power_off();
	NOT_REACHED();
}

void
sys_exit (int status)
{
	printf ("%s: exit(%d)\n", thread_name(), status);
	if (thread_current()->process_status)
			thread_current()->process_status->return_status = status;
	thread_exit();
}

int
sys_write (int fd, const void *buffer, unsigned size)
{
	int ret;

	if(!user_mem_check(buffer, size, false)) return false;

	if (fd == STDOUT_FILENO)
		{
			 putbuf( buffer , size );
			 return size;
		}

	else
		{
			/* later */
			lock_acquire (&filesys_lock);

			struct file *f = get_file_by_fd (fd, GET_FILE);
			if (f == NULL)
				{
					lock_release (&filesys_lock);
					return -1;				
				}

			else
				{
					lock_release (&filesys_lock);
					ret = file_write (f, buffer, size);
					return ret;
				}
		}
}

bool 
sys_read(int fd, void *buffer, unsigned size, int *ret)
{
	uint8_t i;
	uint8_t* local_buf = (uint8_t*)buffer;

	if(!user_mem_check(buffer, size, true)) return false;
	//if (!is_user_vaddr (buffer)) return false;
		
	if (fd == STDIN_FILENO)
		{
			for(i = 0; i < size; i++)
				local_buf[i] = (uint8_t)input_getc();
			
			*ret = size;
		}
	
	else
		{
				/* later */
				lock_acquire (&filesys_lock);

				struct file *f = get_file_by_fd (fd, GET_FILE);
				if (f == NULL)
						*ret = -1;			 
				
				else
						*ret = file_read (f, buffer, size);
				
				lock_release (&filesys_lock);
		}
		return true;
}

pid_t
sys_exec (const char *cmd_line)
{
	int ret;
	ret = process_execute(cmd_line);
	return ret; 
}

int
sys_wait (pid_t pid)
{
	int ret;
	ret = process_wait(pid); 
	return ret;
}

bool
sys_create (const char *file_name, unsigned initial_size, bool *ret)
{
	if (!is_string(file_name)) return false;
	if (file_name[0] == '\0') return false;

	lock_acquire (&filesys_lock);
	*ret = filesys_create (file_name, initial_size);
	lock_release (&filesys_lock);				
	
	return true;
}

bool
sys_remove (const char *file_name, bool *ret)
{
	if (!is_string(file_name)) return false;

	lock_acquire (&filesys_lock);
	*ret = filesys_remove (file_name);
	lock_release (&filesys_lock);
	
	return true;				
}

int
sys_open (const char *file_name)
{
	if (!is_string(file_name)) return -1;
	
	// 1. File open
	lock_acquire (&filesys_lock);
	struct file *f = filesys_open (file_name);
	lock_release (&filesys_lock);
	
	if (!f)	return -1;
	
	struct thread *t = thread_current ();
	int fd_num;

	if (strcmp (t->name, file_name) == 0) file_deny_write (f);
 
	// 2. Allocate FD number
	if (list_empty (&t->fd_list)) fd_num = 2;
	else
		{
			fd_num = list_entry (list_begin (&t->fd_list), struct file_description, elem) -> fd + 1;			
		}		
		
	struct file_description *fd = malloc (sizeof (struct file_description));//palloc_get_page (0);
	if (fd == NULL)	return -1;
	
	fd->fd = fd_num;
	fd->file = f;

	list_push_front (&t->fd_list, &fd->elem);

	return fd_num;
}

bool
sys_close (int fd)
{
	lock_acquire (&filesys_lock);
	struct thread *t = thread_current ();
	struct list_elem *e;
	struct file_description *found = NULL;
	bool success = false;

	if (!list_empty(&t->fd_list))
		{
			for (e = list_begin (&t->fd_list); e != list_end (&t->fd_list); e = list_next (e))
				{
					found = list_entry (e, struct file_description, elem);
				
					if (found->fd == fd)
						{
							file_close (found->file);
							list_remove (e);
							free (found);
							//palloc_free_page(found);			
							success = true;
							break;
						}
				}
		}
	lock_release (&filesys_lock);

	return success;
}

int
sys_filesize (int fd)
{
	int ret = 0;

	lock_acquire (&filesys_lock);
	struct file *f = get_file_by_fd (fd, GET_FILE);
	
	if (f != NULL)
		ret = file_length (f);
	
	lock_release (&filesys_lock);
	return ret;
				
}

bool
sys_seek (int fd, unsigned position)
{
	lock_acquire (&filesys_lock);
	struct file *f = get_file_by_fd (fd, GET_FILE);

	if (f != NULL) file_seek (f, position);

	lock_release (&filesys_lock);

	return (f != NULL);
}

bool
sys_tell (int fd, unsigned *ret)
{
	lock_acquire (&filesys_lock);
	struct file *f = get_file_by_fd (fd, GET_FILE);

	if (f != NULL) *ret = file_tell (f);

	lock_release (&filesys_lock);

	return (f != NULL);
}

struct file *
get_file_by_fd (int fd, int flag)
{
	struct thread *t = thread_current ();
	struct list_elem *e;
	struct file_description *found = NULL;
	
	if (!list_empty (&t->fd_list))
		{
			for (e = list_begin (&t->fd_list); e != list_end(&t->fd_list); e = list_next (e))
				{
					found = list_entry (e, struct file_description, elem);
					
					if (found->fd == fd)
						{
							if ((flag & GET_FILE)) return found->file;		
						}				
				}
		}
		
	return NULL;				
}

int
sys_fibonacci (int n)
{
	int i, a0 = 0, a1 = 1, a2 = 0;
	
	if (n < 0) return -1;
	if (n == 0) return 0;
	if (n == 1) return 1;
					  
	for (i = 1; i < n; i++)
		{
			a2 = a1 + a0;
			a0 = a1;
			a1 = a2;
		}
	return a2;
}

int
sys_sum_of_four_integers (int a, int b, int c, int d)
{
	return a + b + c + d;
}
