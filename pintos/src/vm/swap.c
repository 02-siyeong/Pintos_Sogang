#include <debug.h>
#include <stddef.h>
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "vm/swap.h"

struct swap_table st;

static unsigned 
swap_hash (const struct hash_elem *e, void *aux UNUSED)
{
	const struct swap *s = hash_entry(e, struct swap, hash_elem);
	return hash_bytes( &s->sector, sizeof s->sector);
}

static bool 
swap_less (const struct hash_elem *eA, const struct hash_elem *eB, void * aux UNUSED)
{
	const struct swap *sA = hash_entry(eA, struct swap, hash_elem);
	const struct swap *sB = hash_entry(eB, struct swap, hash_elem);
	return sA->sector < sB->sector;
}

bool 
swap_lookup (size_t sector, void * kpage)
{
	struct hash *swaps = &st.swaps; 
	struct swap s;
	struct hash_elem *e;
	size_t i;
	
	s.sector = sector;
	e = hash_find (swaps, &s.hash_elem);
	
	if (e == NULL)
		return false;
	
	if (kpage != NULL)
		{
			for (i = 0; i < st.sp_pin; i++)
				block_read (st.disk, sector + i, kpage + (i * BLOCK_SECTOR_SIZE));
		}
	return true;
}

void 
swap_init()
{
	hash_init(&st.swaps, swap_hash, swap_less, NULL);
	st.disk = block_get_role (BLOCK_SWAP);
	st.map = bitmap_create (block_size(st.disk));

	if (PGSIZE % BLOCK_SECTOR_SIZE)
		st.sp_pin = PGSIZE/BLOCK_SECTOR_SIZE + 1;
	
	else
		st.sp_pin = PGSIZE/BLOCK_SECTOR_SIZE;
}

size_t 
swap_insert (void *kpage)
{
	struct swap *s;
	size_t sector_num;
	size_t i;

	sector_num = bitmap_scan_and_flip (st.map, 0, st.sp_pin, 0);
	s = calloc (1,sizeof(struct swap));
	s->sector = sector_num;
	
	hash_insert(&st.swaps, &s->hash_elem);
	for (i = 0; i < st.sp_pin; i++)
		block_write (st.disk, sector_num + i, kpage + (i * BLOCK_SECTOR_SIZE));

	return sector_num;
}

void 
swap_delete (size_t sector)
{
	struct swap s;
	struct swap *temp; 
	struct hash_elem *e;

	s.sector = sector;
	e = hash_delete (&st.swaps, &s.hash_elem);
	temp = hash_entry (e, struct swap, hash_elem);
	bitmap_set_multiple (st.map, temp->sector, st.sp_pin, 0);
}
