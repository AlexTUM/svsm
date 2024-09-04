#ifndef __INCLUDE_STREAM_HASH_H
#define __INCLUDE_STREAM_HASH_H
#define HACL_HASH_SHA3_DIGEST_LENGTH 64

#include <stdint.h>
#include "hacl/karamel/include/krml/internal/target.h"
// This is effectively used as a wrapper for Hacl_Hash_SHA3_state_t to hide Hacl 
// intrinsics from the API. The user never needs to inspect the state, only pipe 
// it to update commands.
// Better way to do this? E.g. include Hacl stuff here just to do accurate typedef?
typedef void* hash_state;

typedef struct digest_s_t {
    uint8_t digest[HACL_HASH_SHA3_DIGEST_LENGTH];
    uint32_t size;
} digest_t;

digest_t *alloc_digest();
void free_digest(digest_t *digest);
hash_state hash_init();
uint32_t hash_update(hash_state state, uint8_t *chunk, uint32_t chunk_len);

// finish vs. digest function: finish should also free state memory, as the 
// allocation is hidden from the user. A little less flexibility (no intermediary 
// results) but currently seems like the better option
uint32_t hash_finish(hash_state state, digest_t *output);

#endif // !__INCLUDE_STREAM_HASH_H 
