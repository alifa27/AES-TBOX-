#include "aes_v2.h"

// --- DÉCLARATION DES TABLES EXTERNES ---
// (Contrairement à la V1, on n'importe QUE T0 et InvT0 !)
extern const uint32_t T0[256];
extern const uint8_t SBOX[256];

extern const uint32_t InvT0[256];
extern const uint8_t InvSBOX[256];

// ==========================================
// FONCTION DE CHIFFREMENT (VERSION 2 - 1 Table)
// ==========================================
void AES_Encrypt_V2(uint32_t *state, const uint32_t *RoundKeys, int Nr) {
    uint32_t s0 = state[0] ^ RoundKeys[0];
    uint32_t s1 = state[1] ^ RoundKeys[1];
    uint32_t s2 = state[2] ^ RoundKeys[2];
    uint32_t s3 = state[3] ^ RoundKeys[3];
    uint32_t t0, t1, t2, t3;

    // Tours principaux
    for (int r = 1; r < Nr; r++) {
        // La magie opère ici : on simule T1, T2, T3 avec l'instruction matérielle ROR
        t0 = T0[GET_BYTE_0(s0)] ^ __ROR(T0[GET_BYTE_1(s1)], 8) ^ __ROR(T0[GET_BYTE_2(s2)], 16) ^ __ROR(T0[GET_BYTE_3(s3)], 24) ^ RoundKeys[r*4 + 0];
        t1 = T0[GET_BYTE_0(s1)] ^ __ROR(T0[GET_BYTE_1(s2)], 8) ^ __ROR(T0[GET_BYTE_2(s3)], 16) ^ __ROR(T0[GET_BYTE_3(s0)], 24) ^ RoundKeys[r*4 + 1];
        t2 = T0[GET_BYTE_0(s2)] ^ __ROR(T0[GET_BYTE_1(s3)], 8) ^ __ROR(T0[GET_BYTE_2(s0)], 16) ^ __ROR(T0[GET_BYTE_3(s1)], 24) ^ RoundKeys[r*4 + 2];
        t3 = T0[GET_BYTE_0(s3)] ^ __ROR(T0[GET_BYTE_1(s0)], 8) ^ __ROR(T0[GET_BYTE_2(s1)], 16) ^ __ROR(T0[GET_BYTE_3(s2)], 24) ^ RoundKeys[r*4 + 3];

        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }

    // Dernier tour (SANS MixColumns)
    state[0] = ((uint32_t)SBOX[GET_BYTE_0(s0)])       | ((uint32_t)SBOX[GET_BYTE_1(s1)] << 8) |
               ((uint32_t)SBOX[GET_BYTE_2(s2)] << 16) | ((uint32_t)SBOX[GET_BYTE_3(s3)] << 24) ^ RoundKeys[Nr*4 + 0];

    state[1] = ((uint32_t)SBOX[GET_BYTE_0(s1)])       | ((uint32_t)SBOX[GET_BYTE_1(s2)] << 8) |
               ((uint32_t)SBOX[GET_BYTE_2(s3)] << 16) | ((uint32_t)SBOX[GET_BYTE_3(s0)] << 24) ^ RoundKeys[Nr*4 + 1];

    state[2] = ((uint32_t)SBOX[GET_BYTE_0(s2)])       | ((uint32_t)SBOX[GET_BYTE_1(s3)] << 8) |
               ((uint32_t)SBOX[GET_BYTE_2(s0)] << 16) | ((uint32_t)SBOX[GET_BYTE_3(s1)] << 24) ^ RoundKeys[Nr*4 + 2];

    state[3] = ((uint32_t)SBOX[GET_BYTE_0(s3)])       | ((uint32_t)SBOX[GET_BYTE_1(s0)] << 8) |
               ((uint32_t)SBOX[GET_BYTE_2(s1)] << 16) | ((uint32_t)SBOX[GET_BYTE_3(s2)] << 24) ^ RoundKeys[Nr*4 + 3];
}

// ==========================================
// FONCTION DE DÉCHIFFREMENT (VERSION 2 - 1 Table)
// ==========================================
void AES_Decrypt_V2(uint32_t *state, const uint32_t *RoundKeys, int Nr) {
    uint32_t s0 = state[0] ^ RoundKeys[Nr*4 + 0];
    uint32_t s1 = state[1] ^ RoundKeys[Nr*4 + 1];
    uint32_t s2 = state[2] ^ RoundKeys[Nr*4 + 2];
    uint32_t s3 = state[3] ^ RoundKeys[Nr*4 + 3];
    uint32_t t0, t1, t2, t3;

    for (int r = Nr - 1; r > 0; r--) {
        // Rotation inverse des colonnes (s3, s2, s1) pour le InvShiftRows !
        t0 = InvT0[GET_BYTE_0(s0)] ^ __ROR(InvT0[GET_BYTE_1(s3)], 8) ^ __ROR(InvT0[GET_BYTE_2(s2)], 16) ^ __ROR(InvT0[GET_BYTE_3(s1)], 24) ^ RoundKeys[r*4 + 0];
        t1 = InvT0[GET_BYTE_0(s1)] ^ __ROR(InvT0[GET_BYTE_1(s0)], 8) ^ __ROR(InvT0[GET_BYTE_2(s3)], 16) ^ __ROR(InvT0[GET_BYTE_3(s2)], 24) ^ RoundKeys[r*4 + 1];
        t2 = InvT0[GET_BYTE_0(s2)] ^ __ROR(InvT0[GET_BYTE_1(s1)], 8) ^ __ROR(InvT0[GET_BYTE_2(s0)], 16) ^ __ROR(InvT0[GET_BYTE_3(s3)], 24) ^ RoundKeys[r*4 + 2];
        t3 = InvT0[GET_BYTE_0(s3)] ^ __ROR(InvT0[GET_BYTE_1(s2)], 8) ^ __ROR(InvT0[GET_BYTE_2(s1)], 16) ^ __ROR(InvT0[GET_BYTE_3(s0)], 24) ^ RoundKeys[r*4 + 3];

        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }

    // Dernier tour inverse
    state[0] = ((uint32_t)InvSBOX[GET_BYTE_0(s0)])       | ((uint32_t)InvSBOX[GET_BYTE_1(s3)] << 8) |
               ((uint32_t)InvSBOX[GET_BYTE_2(s2)] << 16) | ((uint32_t)InvSBOX[GET_BYTE_3(s1)] << 24) ^ RoundKeys[0];

    state[1] = ((uint32_t)InvSBOX[GET_BYTE_0(s1)])       | ((uint32_t)InvSBOX[GET_BYTE_1(s0)] << 8) |
               ((uint32_t)InvSBOX[GET_BYTE_2(s3)] << 16) | ((uint32_t)InvSBOX[GET_BYTE_3(s2)] << 24) ^ RoundKeys[1];

    state[2] = ((uint32_t)InvSBOX[GET_BYTE_0(s2)])       | ((uint32_t)InvSBOX[GET_BYTE_1(s1)] << 8) |
               ((uint32_t)InvSBOX[GET_BYTE_2(s0)] << 16) | ((uint32_t)InvSBOX[GET_BYTE_3(s3)] << 24) ^ RoundKeys[2];

    state[3] = ((uint32_t)InvSBOX[GET_BYTE_0(s3)])       | ((uint32_t)InvSBOX[GET_BYTE_1(s2)] << 8) |
               ((uint32_t)InvSBOX[GET_BYTE_2(s1)] << 16) | ((uint32_t)InvSBOX[GET_BYTE_3(s0)] << 24) ^ RoundKeys[3];
}
