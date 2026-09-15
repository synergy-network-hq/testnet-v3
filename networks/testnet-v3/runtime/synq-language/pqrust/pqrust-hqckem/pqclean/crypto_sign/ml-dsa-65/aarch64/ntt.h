#ifndef PQCLEAN_MLDSA65_AARCH64_NTT_H
#define PQCLEAN_MLDSA65_AARCH64_NTT_H

#include "params.h"
#include "NTT_params.h"
#include <stdint.h>

#define constants DILITHIUM_NAMESPACE(constants)
#define streamlined_CT_negacyclic_table_Q1_jump_extended DILITHIUM_NAMESPACE(streamlined_CT_negacyclic_table_Q1_jump_extended)
#define streamlined_GS_itable_Q1_jump_extended DILITHIUM_NAMESPACE(streamlined_GS_itable_Q1_jump_extended)

extern void PQCLEAN_MLDSA65_AARCH64__asm_ntt_SIMD_top(int32_t *des, const int32_t *table, const int32_t *_constants);
extern void PQCLEAN_MLDSA65_AARCH64__asm_ntt_SIMD_bot(int32_t *des, const int32_t *table, const int32_t *_constants);

extern void PQCLEAN_MLDSA65_AARCH64__asm_intt_SIMD_top(int32_t *des, const int32_t *table, const int32_t *_constants);
extern void PQCLEAN_MLDSA65_AARCH64__asm_intt_SIMD_bot(int32_t *des, const int32_t *table, const int32_t *_constants);

extern
const int32_t constants[16];

extern
const int32_t streamlined_CT_negacyclic_table_Q1_jump_extended[((NTT_N - 1) + (1 << 0) + (1 << 4)) << 1];

extern
const int32_t streamlined_GS_itable_Q1_jump_extended[((NTT_N - 1) + (1 << 0) + (1 << 4)) << 1];

#define NTT(in) do { \
        PQCLEAN_MLDSA65_AARCH64__asm_ntt_SIMD_top(in, streamlined_CT_negacyclic_table_Q1_jump_extended, constants); \
        PQCLEAN_MLDSA65_AARCH64__asm_ntt_SIMD_bot(in, streamlined_CT_negacyclic_table_Q1_jump_extended, constants); \
    } while(0)

#define iNTT(in) do { \
        PQCLEAN_MLDSA65_AARCH64__asm_intt_SIMD_bot(in, streamlined_GS_itable_Q1_jump_extended, constants); \
        PQCLEAN_MLDSA65_AARCH64__asm_intt_SIMD_top(in, streamlined_GS_itable_Q1_jump_extended, constants); \
    } while(0)

#define ntt DILITHIUM_NAMESPACE(ntt)
void ntt(int32_t a[ARRAY_N]);
#define invntt_tomont DILITHIUM_NAMESPACE(invntt_tomont)
void invntt_tomont(int32_t a[ARRAY_N]);

#endif