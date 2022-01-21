#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "memlib.h"
#include "mm.h"

/** The required alignment of heap payloads */
const size_t ALIGNMENT = 2 * sizeof(size_t);
const void *error = (void *)-1;

/** The layout of each block allocated on the heap */
typedef struct {
    size_t footer;
    /** The size of the block and whether it is allocated (stored in the low bit) */
    size_t header;
    /**
     * We don't know what the size of the payload will be, so we will
     * declare it as a zero-length array.  This allow us to obtain a
     * pointer to the start of the payload.
     */
    uint8_t payload[];
} block_t;


typedef struct node_t {
    struct node_t *prev;
    struct node_t *next;
} node_t;

//24 bytes total for global variables, 8 for each pointer
node_t *first_free = NULL;
node_t *last_free = NULL;


/** Rounds up `size` to the nearest multiple of `n` */
static size_t round_up(size_t size, size_t n) {
    return (size + (n - 1)) / n * n;
}


static void set_header(block_t *block, size_t size, bool is_allocated) {
    block->header = size | is_allocated;
}

static void set_footer(block_t *block, size_t size, bool is_allocated) {
    size_t *footer = (size_t *) ((void *) block + size + ALIGNMENT);
    *footer = size | is_allocated;
}

static block_t *block_from_payload(void *ptr) {
    return ptr - offsetof(block_t, payload);
}

static block_t *block_from_node(node_t *ptr) {
    return (block_t *) ((void *) ptr - ALIGNMENT);
}

static node_t *node_from_block(block_t *block) {
    return (node_t *) ((void *) block + ALIGNMENT);
}


static size_t get_size(block_t *block) {
    return block->header & ~1;
}

static size_t get_prev_size(block_t *block) {
    return block->footer & ~1;
}


bool is_prev_alloc(block_t *block) {
    return block->footer & 1;
}

bool is_next_alloc(block_t *block) {
    size_t *header = (size_t *) ((void *) block + get_size(block) + sizeof(size_t) + ALIGNMENT);
    if ((*header & ~1) != 0) { //comparing last bit
        return (*header & 1);
    }
    return true;
}

static block_t *get_next_block(block_t *block) {
    return (block_t *) ((void *) block + get_size(block) + ALIGNMENT);
}

block_t *get_prev_block(block_t *block) {
    return (block_t *) ((void *) block - get_prev_size(block) - ALIGNMENT);
}



static void remove_node(block_t *block) {
    node_t *node = node_from_block(block);
    node->next->prev = node->prev;
    node->prev->next = node->next;
    
}

static void add_node(block_t *block) {
    node_t *node = node_from_block(block);
    node->prev = last_free->prev;
    node->next = last_free;
    last_free->prev = node;
    node->prev->next = node;
}


static void split(block_t *block, size_t block_size, size_t size) {
    set_header(block, size, true);
    set_footer(block, size, true);
    block_t *next_block = get_next_block(block);
    set_header(next_block, block_size - size - ALIGNMENT, false);
    set_footer(next_block, block_size - size - ALIGNMENT, false);
    remove_node(block);
    add_node(next_block);
}

static void coalesce(block_t *block, size_t size) {
    if (!is_prev_alloc(block) || !is_next_alloc(block)) {
        if (!is_prev_alloc(block)) {
        size += get_prev_size(block) + ALIGNMENT;
        set_header(get_prev_block(block), size, false);
        set_footer(get_prev_block(block), size, false);
        remove_node(block);
        if (!is_next_alloc(block)) {
            block_t *next_block = get_next_block(block);
            size += get_size(next_block) + ALIGNMENT;
            set_header(get_prev_block(block), size, false);
            set_footer(get_prev_block(block), size, false);
            remove_node(next_block);
            return;
        }
        return;
    }
        if (!is_next_alloc(block)) {
            block_t *next_block = get_next_block(block);
            size += get_size(next_block) + ALIGNMENT;
            set_header(block, size, false);
            set_footer(block, size, false);
            remove_node(next_block);
        }  
    }
}

/* mm_init - Initialize the allocator state */
bool mm_init(void) {
    first_free = (node_t *) mem_sbrk(ALIGNMENT);
    last_free = (node_t *) mem_sbrk(ALIGNMENT);

    if ((first_free == error) || (last_free == error)) {
        return false;
    }
    first_free->next = last_free;
    last_free->prev = first_free;
    last_free->next = NULL;
    first_free->prev = NULL;
    size_t *prologue = (size_t *) mem_sbrk(sizeof(size_t));
    size_t *epilogue = (size_t *) mem_sbrk(sizeof(size_t));
    if ((prologue == error) || (epilogue == error)) {return false;}
    *prologue = 1;
    *epilogue = 1;
    return true;
}


static block_t *find_fit(size_t size) {
    node_t *node = last_free->prev;
    while(node != first_free){
        block_t *block = block_from_node(node);
        size_t block_size = get_size(block);
        if (block_size >= size) {
            set_header(block, block_size, true);
            set_footer(block, block_size, true);
            if (block_size < size + 2*ALIGNMENT) {
                remove_node(block);
                return block;
            }
            split(block, block_size, size);
            return block;
        }
        node = node->prev;
    }
    return NULL;
}

/* mm_malloc - Allocates a block with the given size */
void *mm_malloc(size_t size) {
    size = round_up(size, ALIGNMENT);
    // If there is a large enough free block, use it.
    block_t *block = find_fit(size);
    if (block != NULL) {
        return block->payload;
    }
    block = (block_t *) (mem_sbrk(size) - ALIGNMENT);
    size_t *new_footer = (size_t *) mem_sbrk(sizeof(size_t));
    if (new_footer == error) {
        return NULL;
    }
    if (block == error) {
        return NULL;
    }
    size_t *epilogue = (size_t *) mem_sbrk(sizeof(size_t));
    *epilogue = 1;
    set_header(block, size, true);
    set_footer(block, size, true);
    return block->payload;
}

/* mm_free - Releases a block to be reused for future allocations. */
void mm_free(void *ptr) {
    if (ptr == NULL) {
        return; // mm_free(NULL) does nothing.
    }
    block_t *block = block_from_payload(ptr);
    size_t block_size = get_size(block);
    set_header(block, block_size, false);
    set_footer(block, block_size, false);
    add_node(block);
    coalesce(block, block_size);
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