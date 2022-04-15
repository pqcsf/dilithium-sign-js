#ifndef SIGN_H
#define SIGN_H

#include <stddef.h>
#include <stdint.h>
#include "params.h"
#include "polyvec.h"
#include "poly.h"

#ifdef __cplusplus
extern "C" {
#endif

bool dilithiumGenkey(uint8_t *genKeySeed, uint8_t *pk, uint8_t *sk);
bool dilithiumPublicKeyCreate(const uint8_t *sk, uint8_t *pk);
bool dilithiumSign(uint8_t *sm, uint8_t *m, const uint8_t *sk, uint8_t *salt);
bool dilithiumVerify(uint8_t *sm, uint8_t *m, const uint8_t *pk);

#ifdef __cplusplus
}
#endif

#endif
