# cardano-mempool

Thread-safe lock-free memory pool.

Memory management utility that allows allocating large chunks of memory at once while
using it at a fine grain smaller block level.

The particular use cases in Cardano is to allocate one large page of memlocked memory and
treat it as many smaller regions for secure storage of private keys.
