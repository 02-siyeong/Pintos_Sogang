#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

/* User Addtional System Functions */
void sys_halt (void);
void sys_exit (int status);

#endif /* userprog/syscall.h */
