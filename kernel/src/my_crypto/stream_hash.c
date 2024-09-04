#include "stream_hash.h"
#include "hacl/include/Hacl_Hash_SHA3.h"
#include "hacl/include/Hacl_Streaming_Types.h"
#include <stdint.h>

digest_t *alloc_digest() {
    // what kind of alloc here? do we need kmalloc? karamel seems to use malloc
    // generally karamel seems to use stdlib, would that not be unavailable in kernel?
    digest_t *hash_digest = KRML_HOST_MALLOC(sizeof (digest_t));
    hash_digest->size = HACL_HASH_SHA3_DIGEST_LENGTH;
    return hash_digest;
}

void free_digest(digest_t *digest) {
    KRML_HOST_FREE(digest);
}

hash_state hash_init() {
    Hacl_Hash_SHA3_state_t *state = Hacl_Hash_SHA3_malloc(Spec_Hash_Definitions_SHA3_512);
    return (hash_state)state;
}

uint32_t hash_update(hash_state state, uint8_t *chunk, uint32_t chunk_len) {
    uint32_t result = Hacl_Hash_SHA3_update(state, chunk, chunk_len);
    return result;
}

uint32_t hash_finish(hash_state state, digest_t *output) {
    uint32_t result = Hacl_Hash_SHA3_digest(state, output->digest);
    Hacl_Hash_SHA3_free(state);
    return result;
}
