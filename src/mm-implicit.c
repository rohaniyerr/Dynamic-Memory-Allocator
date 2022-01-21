/*
 * mm-implicit.c - The best malloc package EVAR!
 *
 * TODO (bug): mm_realloc and mm_calloc don't seem to be working...
 * TODO (bug): The allocator doesn't re-use space very well...
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "memlib.h"
#include "mm.h"

/** The required alignment of heap payloads */
const size_t ALIGNMENT = 2 * sizeof(size_t);

/** The layout of each block allocated on the heap */
typedef struct {
    /** The size of the block and whether it is allocated (stored in the low bit) */
    size_t header;
    /**
     * We don't know what the size of the payload will be, so we will
     * declare it as a zero-length array.  This allow us to obtain a
     * pointer to the start of the payload.
     */
    uint8_t payload[];
} block_t;

/** The first and last blocks on the heap */
static block_t *mm_heap_first = NULL;
static block_t *mm_heap_last = NULL;

/** Rounds up `size` to the nearest multiple of `n` */
static size_t round_up(size_t size, size_t n) {
    return (size + (n - 1)) / n * n;
}

/** Set's a block's header with the given size and allocation state */
static void set_header(block_t *block, size_t size, bool is_allocated) {
    block->header = size | is_allocated;
}

/** Extracts a block's size from its header */
static size_t get_size(block_t *block) {
    return block->header & ~1;
}

/** Extracts a block's allocation state from its header */
static bool is_allocated(block_t *block) {
    return block->header & 1;
}

/**
 * Finds the first free block in the heap with at least the given size.
 * If no block is large enough, returns NULL.
 */
static block_t *find_fit(size_t size) {
    // Traverse the blocks in the heap using the implicit list
    for (block_t *curr = mm_heap_first; mm_heap_last != NULL && curr <= mm_heap_last;
         curr = (void *) curr + get_size(curr)) {
        // If the block is free and large enough for the allocation, return it
        if (!is_allocated(curr) && get_size(curr) >= size) {
            return curr;
        }
    }
    return NULL;
}

/** Gets the header corresponding to a given payload pointer */
static block_t *block_from_payload(void *ptr) {
    return ptr - offsetof(block_t, payload);
}

/**
 * mm_init - Initializes the allocator state
 */
bool mm_init(void) {
    // We want the first payload to start at ALIGNMENT bytes from the start of the heap
    void *padding = mem_sbrk(ALIGNMENT - sizeof(block_t));
    if (padding == (void *) -1) {
        return false;
    }

    // Initialize the heap with no blocks
    mm_heap_first = NULL;
    mm_heap_last = NULL;

    return true;
}

void mm_coalesce(void){
    void *curr = mm_heap_first;
    while(curr < (void *) mm_heap_last){
        size_t curr_size = get_size((block_t *) curr);
        void *next = curr + curr_size;
        size_t next_size = get_size((block_t *) next);
        if(next > (void *) mm_heap_last){break;}
        if(!is_allocated(curr) && !is_allocated(next)){
            if((block_t *) (next + next_size) == mm_heap_last){
                mm_heap_last = curr;
            }
            set_header((block_t *) curr, curr_size + next_size, false);
        }
        else if(is_allocated(curr) && !is_allocated(next)){
            curr = next;
        }
        else{
            curr += curr_size + next_size;
        }
    }
}

/**
 * mm_malloc - Allocates a block with the given size
 */
void *mm_malloc(size_t size) {
    // The block must have enough space for a header and be 16-byte aligned
    size = round_up(sizeof(block_t) + size, ALIGNMENT);
    //coalescing
    mm_coalesce();
    // If there is a large enough free block, use it
    block_t *block = find_fit(size);
    size_t block_size = get_size(block);
    if (block != NULL) {
        if(size < block_size){
            set_header(block, size, true);
            block_t *split_block = (block_t *) (((void *) (block)) + size);
            set_header(split_block, block_size-size, false);
            if(block == mm_heap_last){
                mm_heap_last = split_block;
            }
        }
        else{
            set_header(block, block_size, true);
        }
        return block->payload;
    }

    // Otherwise, a new block needs to be allocated at the end of the heap
    block = mem_sbrk(size);
    if (block == (void *) -1) {
        return NULL;
    }

    // Update mm_heap_first and mm_heap_last since we extended the heap
    if (mm_heap_first == NULL) {
        mm_heap_first = block;
    }
    mm_heap_last = block;

    // Initialize the block with the allocated size
    set_header(block, size, true);
    return block->payload;
}

/**
 * mm_free - Releases a block to be reused for future allocations
 */
void mm_free(void *ptr) {
    // mm_free(NULL) does nothing
    if (ptr == NULL) {
        return;
    }

    // Mark the block as unallocated
    block_t *block = block_from_payload(ptr);
    set_header(block, get_size(block), false);
}

/**
 * mm_realloc - Change the size of the block by mm_mallocing a new block,
 *      copying its data, and mm_freeing the old block.
 */
void *mm_realloc(void *old_ptr, size_t size) {
    if(size == 0){
        mm_free(old_ptr);
        return NULL;
    }
    if(old_ptr == NULL){
        return mm_malloc(size);
    }
    void *new_mem = mm_malloc(size);
    if(!new_mem){
        return NULL;
    }
    size_t old_size = get_size(old_ptr);
    if(size < old_size){
        old_size = size;
        memcpy(new_mem, old_ptr, old_size);
    }
    mm_free(old_ptr);
    return new_mem;

}

/**
 * mm_calloc - Allocate the block and set it to zero.
 */
void *mm_calloc(size_t nmemb, size_t size) {
    char *new_mem = (char *) mm_malloc(size);
    memset(new_mem, 0, nmemb * size);
    return (void *) new_mem;
}

/**
 * mm_checkheap - So simple, it doesn't need a checker!
 */
void mm_checkheap(void) {

}
