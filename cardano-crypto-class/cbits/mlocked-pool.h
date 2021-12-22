// mlocked-pool.h
//
// A special-purpose memory allocator for space-efficient use of mlocked
// memory.
// This allocator uses a memory pool behind the scenes, allocating page-sized
// chunks of mlocked memory, and then handing out item-sized chunks of them
// using a stack of pointers.
//
// The item size of 32 bytes was chosen to accommodate Ed25519 sign keys; by
// packing such keys tightly into pages, we can accommodate 128 individual keys
// per 4kiB page.

#define POOL_ITEM_SIZE 32U

// Allocate POOL_ITEM_SIZE bytes of memory. It is possible to demand any other
// size; however, demanding more than POOL_ITEM_SIZE bytes will cause this
// function to fail by returning NULL, and demanding less will cause it to
// still allocate POOL_ITEM_SIZE bytes.
void* mlocked_pool_malloc(size_t);

// Free memory previously allocated with mlocked_stack_malloc.
//
// WARNING: do not pass memory to this function that was not originally
// allocated by mlocked_stack_malloc. Doing so will mark the memory you passed
// as available for future allocations, and it will end up being returned from
// mlocked_stack_malloc() without actually being mlocked.
void mlocked_pool_free(void* item);
