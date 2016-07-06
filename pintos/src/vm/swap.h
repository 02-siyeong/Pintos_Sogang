#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <hash.h>
#include "devices/block.h"
#include <bitmap.h>

extern struct swap_table st;

struct swap_table
	{
		struct hash swaps;
		struct bitmap* map;
		struct block* disk;
		
		size_t sp_pin;
	};

struct swap
	{
		struct hash_elem hash_elem;
		block_sector_t sector;
	};

void swap_init (void);
size_t swap_insert (void *kswap);
bool swap_lookup (size_t sector, void * kpage);
void swap_delete (size_t sector);

#endif
