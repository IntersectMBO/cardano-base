#include <stdlib.h>
#include <sodium.h>
#include <memory.h>
#include <assert.h>
#include <stdbool.h>

#define POOL_ITEM_SIZE 32U

#ifndef DEFAULT_PAGE_SIZE
# ifdef PAGE_SIZE
#  define DEFAULT_PAGE_SIZE PAGE_SIZE
# else
#  define DEFAULT_PAGE_SIZE 0x10000
# endif
#endif

typedef struct mlocked_pool_t mlocked_pool_t;

static void mlocked_pool_init(mlocked_pool_t *p);
static void mlocked_pool_reset(mlocked_pool_t *p);
static void mlocked_pool_grow(mlocked_pool_t *p);
static void mlocked_stack_grow(mlocked_pool_t *p);
static void mlocked_stack_push(mlocked_pool_t *p, void* val);
static bool mlocked_stack_pop(void** dst, mlocked_pool_t *p);

typedef struct mlocked_pool_t {
    void **stack;
    void **pool;
    size_t stack_cap;
    size_t stack_top;
    size_t pool_size;
} mlocked_pool_t;

static void mlocked_pool_init(mlocked_pool_t *p)
{
    memset(p, 0, sizeof(mlocked_pool_t));
}

static void mlocked_pool_reset(mlocked_pool_t *p)
{
    free(p->stack);
    for (size_t i = 0; i < p->pool_size; ++i) {
        sodium_free(p->pool[i]);
    }
    free(p->pool);
    mlocked_pool_init(p);
}

static void mlocked_pool_grow(mlocked_pool_t *p)
{
    size_t i;
    void* new_page;

    p->pool_size++;
    p->pool = realloc(p->pool, p->pool_size);
    new_page = sodium_malloc(DEFAULT_PAGE_SIZE);
    p->pool[p->pool_size - 1] = new_page;
    for (i = 0; i < DEFAULT_PAGE_SIZE; i += POOL_ITEM_SIZE) {
        mlocked_stack_push(p, new_page + i);
    }
}

static void mlocked_stack_grow(mlocked_pool_t *p)
{
    size_t i;

    p->stack_cap <<= 1;
    p->stack = realloc(p->stack, p->stack_cap);
}

static void mlocked_stack_push(mlocked_pool_t *p, void* val)
{
    if (p->stack_top >= p->stack_cap) {
        mlocked_stack_grow(p);
    }
    p->stack[(p->stack_top)++] = val;
}

static bool mlocked_stack_pop(void** dst, mlocked_pool_t *p)
{
    if (p->stack_top == 0)
        return false;
    *dst = p->stack[--(p->stack_top)];
    return true;
}

static mlocked_pool_t global_pool;
static bool initialized = false;

static void mlocked_atexit()
{
    mlocked_pool_reset(&global_pool);
}

void* mlocked_stack_malloc(size_t size)
{
    void* item;
    bool success;

    assert(size <= POOL_ITEM_SIZE);

    if (size > POOL_ITEM_SIZE)
        return NULL;

    if (!initialized) {
        mlocked_pool_init(&global_pool);
        atexit(mlocked_atexit);
        initialized = true;
    }
    if (global_pool.stack_top >= global_pool.stack_cap) {
        mlocked_pool_grow(&global_pool);
    }
    success = mlocked_stack_pop(&item, &global_pool);
    assert(success);
    return item;
}

void mlocked_free(void* item)
{
    assert(initialized);
    sodium_memzero(item, POOL_ITEM_SIZE);
    mlocked_stack_push(&global_pool, item);
}
