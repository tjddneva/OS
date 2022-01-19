#include <debug.h>
#include <string.h>
#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "threads/synch.h"

struct buffer_cache_entry {
  bool valid_bit;
  bool reference_bit;
  bool dirty_bit;
  block_sector_t disk_sector;
  uint8_t buffer[BLOCK_SECTOR_SIZE];
};
#define NUM_CACHE 64
static struct buffer_cache_entry cache[NUM_CACHE];
static struct lock buffer_cache_lock;

struct buffer_cache_entry* buffer_cache_lookup (block_sector_t);
struct buffer_cache_entry* buffer_cache_select_victim(void);
void buffer_cache_flush(struct buffer_cache_entry*);

void
buffer_cache_init (void)
{
  lock_init (&buffer_cache_lock);

  size_t i;
  for (i = 0; i < NUM_CACHE; ++ i)
  {
    cache[i].valid_bit = false;
  }
}

void
buffer_cache_terminate(void)
{
  lock_acquire (&buffer_cache_lock);

  size_t i;
  for (i = 0; i < NUM_CACHE; ++ i)
  {
    if (cache[i].dirty_bit == false) continue;
    buffer_cache_flush( &(cache[i]) );
  }

  lock_release (&buffer_cache_lock);
}

void
buffer_cache_read (block_sector_t sector, void *target)
{
  lock_acquire (&buffer_cache_lock);

  struct buffer_cache_entry *slot = buffer_cache_lookup (sector);
  if (slot == NULL) {	
	size_t i = 0;
	for(i=0; i<NUM_CACHE; i++){
		if(cache[i].valid_bit == false){
			slot = &cache[i];
			break;
		}
	}
	if(i==NUM_CACHE){
		slot = buffer_cache_select_victim();
	}
    ASSERT (slot != NULL);

    slot->valid_bit = true;
    slot->disk_sector = sector;
    slot->dirty_bit = false;
    block_read (fs_device, sector, slot->buffer);
  }

  slot->reference_bit = true;
  memcpy (target, slot->buffer, BLOCK_SECTOR_SIZE);

  lock_release (&buffer_cache_lock);
}

void
buffer_cache_write (block_sector_t sector, const void *source)
{
  lock_acquire (&buffer_cache_lock);

  struct buffer_cache_entry *slot = buffer_cache_lookup (sector);
  if (slot == NULL) {
	size_t i = 0;
	for(i=0; i<NUM_CACHE; i++){
		if(cache[i].valid_bit == false){
			slot = &cache[i];
			break;
		}
	}
	if(i==NUM_CACHE){
		slot = buffer_cache_select_victim();
	}
    ASSERT (slot != NULL);

    slot->valid_bit = true;
    slot->disk_sector = sector;
    block_read (fs_device, sector, slot->buffer);
  }

  slot->reference_bit = true;
  slot->dirty_bit = true;
  memcpy (slot->buffer, source, BLOCK_SECTOR_SIZE);

  lock_release (&buffer_cache_lock);
}

struct buffer_cache_entry*
buffer_cache_lookup (block_sector_t sector)
{
  size_t i;
  for (i = 0; i < NUM_CACHE; ++ i)
  {
    if (cache[i].valid_bit == false) continue;
    if (cache[i].disk_sector == sector) {
      return &(cache[i]);
    }
  }
  return NULL; 
}

struct buffer_cache_entry*
buffer_cache_select_victim (void)
{
  ASSERT (lock_held_by_current_thread(&buffer_cache_lock));

  static size_t clock_hand = 0;
  while (true) {
    if (cache[clock_hand].reference_bit) {
      cache[clock_hand].reference_bit = false;
    }
    else break;

    clock_hand ++;
    clock_hand %= NUM_CACHE;
  }

  struct buffer_cache_entry *slot = &cache[clock_hand];
  if (slot->dirty_bit) {
    buffer_cache_flush (slot);
  }
  
  return slot;
}

void
buffer_cache_flush (struct buffer_cache_entry *entry)
{
  ASSERT (lock_held_by_current_thread(&buffer_cache_lock));
  ASSERT (entry != NULL && entry->valid_bit == true);

  block_write (fs_device, entry->disk_sector, entry->buffer);
  entry->dirty_bit = false;
}
