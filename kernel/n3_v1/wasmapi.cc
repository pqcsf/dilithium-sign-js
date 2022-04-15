#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "ems.h"
#include "dilithium/sign.h"
#include "dilithium/params.h"

EM_PORT_API(uint32_t) getSkByte() 
{
	return CRYPTO_SECRETKEYBYTES;
}

EM_PORT_API(uint32_t) getPkByte() 
{
	return CRYPTO_PUBLICKEYBYTES;
}

EM_PORT_API(uint32_t) getCryptoByte()
{
	return CRYPTO_BYTES;
}

EM_PORT_API(uint32_t) getGenKeySeedByte()
{
	return SEEDBYTES;
}

EM_PORT_API(uint32_t) getCryptoNonceByte()
{
	return CRHBYTES;
}

EM_PORT_API(uint32_t) getCryptoSaltByte()
{
	return CRHBYTES;
}

/**
 * @param genKeySeed input
 * @param pk output
 * @param sk output
 */
EM_PORT_API(bool) genkey(uint8_t *genKeySeed, uint8_t *pk, uint8_t *sk)
{   
	return dilithiumGenkey(genKeySeed, pk, sk);
}

/**
 * @param sk input
 * @param pk output
 */
EM_PORT_API(bool) publicKeyCreate(const uint8_t *sk, uint8_t *pk)
{
	return dilithiumPublicKeyCreate(sk, pk);
}

/**
 * @param sm output
 * @param m input; Format: | nlen: uint64 (8 bytes) | msg data ... (nlen bytes) | 
 * @param sk input
 * @param salt input
 */
EM_PORT_API(bool) sign(uint8_t *sm, uint8_t *m, const uint8_t *sk, uint8_t *salt)
{   
	return dilithiumSign(sm, m, sk, salt);
}
#include "stdio.h"
/**
 * @param sm output
 * @param m input; Format: | nlen: uint64 (8 bytes) | msg data ... (nlen bytes) | 
 * @param pk input
 */
EM_PORT_API(bool) verify(uint8_t *sm, uint8_t *m, const uint8_t *pk)
{   
	return dilithiumVerify(sm, m, pk);
}

EM_PORT_API(uint8_t*) newByte(uint64_t length)
{
	return (uint8_t*)malloc(length * sizeof(uint8_t));
}

EM_PORT_API(void) freeBuf(uint8_t* ptr)
{
	free(ptr);
}

EM_PORT_API(void) freeBufSafe(uint8_t* ptr, uint64_t length)
{
	memset(ptr, 0, length);
	free(ptr);
}