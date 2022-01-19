#ifndef VM_SWAP_H
#define VM_SWAP_H
typedef uint32_t swap_index_t;

/* Initialize the swap table. */
void vm_swap_init(void);

/* swap out : write the content of page into the swap disk
and return the index of swap region. */
swap_index_t vm_swap_out(void *page);

/* swap in : read the content through the index from the mapped block
and store into page. */
void vm_swap_in(swap_index_t swap_index, void *page);

/* Free the swap region. */
void vm_swap_free(swap_index_t swap_index);
#endif

