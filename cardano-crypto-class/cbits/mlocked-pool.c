#include <stdlib.h>
#include <sodium.h>
#include <memory.h>
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

// Pool size was picked to fit one Ed25519 signing key (32 octets).

#define POOL_ITEM_SIZE 32U

static size_t page_size = 4096U;
typedef struct mlocked_pool_t mlocked_pool_t;

static void mlocked_pool_init();
static void mlocked_pool_reset(mlocked_pool_t *p);
static void mlocked_pool_grow(mlocked_pool_t *p);
static void mlocked_pool_stack_grow(mlocked_pool_t *p);
static void mlocked_pool_stack_push(mlocked_pool_t *p, void* val);
static bool mlocked_pool_stack_pop(void** dst, mlocked_pool_t *p);

typedef struct mlocked_pool_t {
    void **stack;
    void **pool;
    size_t stack_cap;
    size_t stack_top;
    size_t pool_size;
} mlocked_pool_t;

static pthread_once_t mlocked_pool_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t mlocked_pool_mutex;

static mlocked_pool_t global_pool;

static void mlocked_pool_atexit()
{
    pthread_mutex_lock(&mlocked_pool_mutex);
    fprintf(stderr, "mlocked_pool_atexit %i x %u\n", global_pool.pool_size, page_size);
    mlocked_pool_reset(&global_pool);
    pthread_mutex_unlock(&mlocked_pool_mutex);
}

static void mlocked_pool_init()
{
    #if 0
    #ifdef _SC_PAGESIZE
    page_size = sysconf(_SC_PAGESIZE);
    #endif
    #endif
    pthread_mutex_init(&mlocked_pool_mutex, NULL);
    // fprintf(stderr, "mlocked_pool_init\n");
    pthread_mutex_lock(&mlocked_pool_mutex);
    memset(&global_pool, 0, sizeof(mlocked_pool_t));
    pthread_mutex_unlock(&mlocked_pool_mutex);
    atexit(mlocked_pool_atexit);
}

static void mlocked_pool_reset(mlocked_pool_t *p)
{
    // fprintf(stderr, "mlocked_pool_reset\n");
    free(p->stack);
    for (size_t i = 0; i < p->pool_size; ++i) {
        sodium_free(p->pool[i]);
    }
    free(p->pool);
    memset(&global_pool, 0, sizeof(mlocked_pool_t));
}

static void mlocked_pool_grow(mlocked_pool_t *p)
{
    size_t i;
    void* new_page;

    p->pool_size++;
    fprintf(stderr, "mlocked_pool_grow %i x %u\n", p->pool_size, page_size);
    p->pool = realloc(p->pool, p->pool_size * sizeof(void*));
    new_page = sodium_malloc(page_size);
    p->pool[p->pool_size - 1] = new_page;
    for (i = 0; i < page_size; i += POOL_ITEM_SIZE) {
        mlocked_pool_stack_push(p, new_page + i);
    }
}

static void mlocked_pool_stack_grow(mlocked_pool_t *p)
{
    size_t i;

    // fprintf(stderr, "mlocked_pool_stack_grow\n");
    // Just pick a reasonable lower limit for the size.
    if (p->stack_cap < 64)
        p->stack_cap = 64;
    else
        p->stack_cap <<= 1;
    fprintf(stderr, "mlocked_pool_stack_grow %i\n", p->stack_cap);
    p->stack = realloc(p->stack, p->stack_cap * sizeof(void*));
}

static void mlocked_pool_stack_push(mlocked_pool_t *p, void* val)
{
    // fprintf(stderr, "mlocked_pool_stack_push\n");
    if (p->stack_top >= p->stack_cap) {
        mlocked_pool_stack_grow(p);
    }
    p->stack[(p->stack_top)++] = val;
}

static bool mlocked_pool_stack_pop(void** dst, mlocked_pool_t *p)
{
    // fprintf(stderr, "mlocked_pool_stack_pop\n");
    if (p->stack_top == 0)
        return false;
    *dst = p->stack[--(p->stack_top)];
    return true;
}

void* mlocked_pool_malloc(size_t size)
{
    void* item;
    bool success;

    assert(size <= POOL_ITEM_SIZE);

    // fprintf(stderr, "mlocked_pool_malloc(%i)\n", size);

    if (size > POOL_ITEM_SIZE)
        return NULL;

    pthread_once(&mlocked_pool_once, mlocked_pool_init);
    pthread_mutex_lock(&mlocked_pool_mutex);

    if (global_pool.stack_top == 0) {
        mlocked_pool_grow(&global_pool);
    }
    success = mlocked_pool_stack_pop(&item, &global_pool);

    pthread_mutex_unlock(&mlocked_pool_mutex);

    assert(success);
    return item;
}

void mlocked_pool_free(void* item)
{
    pthread_once(&mlocked_pool_once, mlocked_pool_init);
    pthread_mutex_lock(&mlocked_pool_mutex);
    // fprintf(stderr, "mlocked_pool_free(%p)\n", item);
    sodium_memzero(item, POOL_ITEM_SIZE);
    mlocked_pool_stack_push(&global_pool, item);
    pthread_mutex_unlock(&mlocked_pool_mutex);
}
