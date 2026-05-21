#ifndef AES_V2_H
#define AES_V2_H

#include <stdint.h>
#include "stm32wbxx_hal.h" // Donne accès à la macro __ROR du Cortex-M4

// Macros ultra-rapides pour extraire les octets d'un registre 32 bits
#define GET_BYTE_0(x) ((x) & 0xFF)
#define GET_BYTE_1(x) (((x) >> 8) & 0xFF)
#define GET_BYTE_2(x) (((x) >> 16) & 0xFF)
#define GET_BYTE_3(x) (((x) >> 24) & 0xFF)

// Signatures des fonctions
void AES_Encrypt_V2(uint32_t *state, const uint32_t *RoundKeys, int Nr);
void AES_Decrypt_V2(uint32_t *state, const uint32_t *RoundKeys, int Nr);

#endif // AES_V2_H
