#include <bitmap.h>
#include "vm/swap.h"
#include "threads/vaddr.h"
#include "devices/block.h"

static struct block *swap_block;
static struct bitmap *available_swap;

static const size_t SECTORS_PER_PAGE = PGSIZE / BLOCK_SECTOR_SIZE; 
static size_t swap_size;

/* Initialize the swap table. */
void vm_swap_init(void){
    ASSERT(SECTORS_PER_PAGE > 0);

    // Initialize the swap disk
    swap_block = block_get_role(BLOCK_SWAP);
    if(swap_block == NULL){
        PANIC("Cannot initialize the swap block");
        NOT_REACHED();
    }

    /* Initialize the available_swap
    each single bit of available swap corresponds to a block region.
    It consists of contiguous SECTORS_PER_PAGE sectors, 
    and the total size becomes PGSIZE.
    */
    swap_size = block_size(swap_block) / SECTORS_PER_PAGE;
    available_swap = bitmap_create(swap_size);
    bitmap_set_all(available_swap, true);
}

/* swap out : write the content of page into the swap disk
and return the index of swap region. */
swap_index_t vm_swap_out(void *page){
    
    size_t swap_index = bitmap_scan(available_swap, 0 , 1, true);
	if(swap_index == BITMAP_ERROR){
		PANIC("BITMAP ERROR SWAP INDEX DOOMED");
	}
    size_t i;
    for(i = 0;i < SECTORS_PER_PAGE;i++){
        block_write(swap_block, swap_index * SECTORS_PER_PAGE + i, page+(BLOCK_SECTOR_SIZE * i));
    }

    bitmap_set(available_swap, swap_index, false);
    return swap_index;
}

/* swap in : read the content through the index from the mapped block
and store into page. */
void vm_swap_in(swap_index_t swap_index, void *page){
    
    if(bitmap_test(available_swap, swap_index) == true){
        PANIC("Invalid read access to unassinged swap block");
    }

    size_t i;
    for(i = 0;i < SECTORS_PER_PAGE;i++){
        block_read(swap_block,swap_index * SECTORS_PER_PAGE + i, page + (BLOCK_SECTOR_SIZE * i));
    }
    bitmap_set(available_swap, swap_index, true);
}

/* Free the swap region. */
void vm_swap_free(swap_index_t swap_index){
    ASSERT(swap_index < swap_size);
    if(bitmap_test(available_swap, swap_index) == true){
        PANIC("Invalid read access to unassinged swap block");
    }
    bitmap_set(available_swap, swap_index, true);
}

