#include <stdint.h>
#include <string.h>

#include "address.h"
#include "sha2_offsets.h"
#include "utils.h"

void set_layer_addr(uint32_t addr[8], uint32_t layer) {
    ((unsigned char *)addr)[SPX_OFFSET_LAYER] = (unsigned char)layer;
}

void set_tree_addr(uint32_t addr[8], uint64_t tree) {
    ull_to_bytes(&((unsigned char *)addr)[SPX_OFFSET_TREE], 8, tree );
}

void set_type(uint32_t addr[8], uint32_t type) {
    ((unsigned char *)addr)[SPX_OFFSET_TYPE] = (unsigned char)type;
}

void copy_subtree_addr(uint32_t out[8], const uint32_t in[8]) {
    memcpy( out, in, SPX_OFFSET_TREE + 8 );
}

void set_keypair_addr(uint32_t addr[8], uint32_t keypair) {
    ((unsigned char *)addr)[SPX_OFFSET_KP_ADDR1] = (unsigned char)keypair;
}

void copy_keypair_addr(uint32_t out[8], const uint32_t in[8]) {
    memcpy( out, in, SPX_OFFSET_TREE + 8 );
    ((unsigned char *)out)[SPX_OFFSET_KP_ADDR1] = ((unsigned char *)in)[SPX_OFFSET_KP_ADDR1];
}

void set_chain_addr(uint32_t addr[8], uint32_t chain) {
    ((unsigned char *)addr)[SPX_OFFSET_CHAIN_ADDR] = (unsigned char)chain;
}

void set_hash_addr(uint32_t addr[8], uint32_t hash) {
    ((unsigned char *)addr)[SPX_OFFSET_HASH_ADDR] = (unsigned char)hash;
}

void set_tree_height(uint32_t addr[8], uint32_t tree_height) {
    ((unsigned char *)addr)[SPX_OFFSET_TREE_HGT] = (unsigned char)tree_height;
}

void set_tree_index(uint32_t addr[8], uint32_t tree_index) {
    u32_to_bytes(&((unsigned char *)addr)[SPX_OFFSET_TREE_INDEX], tree_index );
}