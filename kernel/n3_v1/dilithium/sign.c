/* ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2022  dilithium JS(WASM) API
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @author  PQCSF
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "params.h"
#include "sign.h"
#include "packing.h"
#include "polyvec.h"
#include "poly.h"
#include "randombytes.h"
#include "symmetric.h"
#include "fips202.h"

//----- dilithium JS(WASM) API -----
bool dilithiumGenkey(uint8_t *genKeySeed, uint8_t *pk, uint8_t *sk)
{
	uint8_t seedbuf[3*SEEDBYTES];
	uint8_t tr[CRHBYTES];
	const uint8_t *rho, *rhoprime, *key;
	polyvecl mat[K];
	polyvecl s1, s1hat;
	polyveck s2, t1, t0;

	/* Get randomness for rho, rhoprime and key */
	// randombytes(seedbuf, SEEDBYTES);
	memcpy(seedbuf, genKeySeed, SEEDBYTES); //not random

	shake256(seedbuf, 3*SEEDBYTES, seedbuf, SEEDBYTES);
	rho = seedbuf;
	rhoprime = seedbuf + SEEDBYTES;
	key = seedbuf + 2*SEEDBYTES;

	/* Expand matrix */
	polyvec_matrix_expand(mat, rho);

	/* Sample short vectors s1 and s2 */
	polyvecl_uniform_eta(&s1, rhoprime, 0);
	polyveck_uniform_eta(&s2, rhoprime, L);

	/* Matrix-vector multiplication */
	s1hat = s1;
	polyvecl_ntt(&s1hat);
	polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
	polyveck_reduce(&t1);
	polyveck_invntt_tomont(&t1);

	/* Add error vector s2 */
	polyveck_add(&t1, &t1, &s2);

	/* Extract t1 and write public key */
	polyveck_caddq(&t1);
	polyveck_power2round(&t1, &t0, &t1);
	pack_pk(pk, rho, &t1);

	/* Compute CRH(rho, t1) and write secret key */
	crh(tr, pk, CRYPTO_PUBLICKEYBYTES);
	pack_sk(sk, rho, tr, key, &t0, &s1, &s2);

	return 1;
}

bool dilithiumPublicKeyCreate(const uint8_t *sk, uint8_t *pk)
{
	uint8_t seedbuf[2*SEEDBYTES + 3*CRHBYTES];
	uint8_t *tr;
	uint8_t *rho, *key;
	polyvecl mat[K];
	polyvecl s1, s1hat;
	polyveck s2, t1, t0;
	
	rho = seedbuf;
	tr = rho + SEEDBYTES;
	key = tr + CRHBYTES;

	unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

	polyvec_matrix_expand(mat, rho);

	s1hat = s1;
	polyvecl_ntt(&s1hat);
	polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
	polyveck_reduce(&t1);
	polyveck_invntt_tomont(&t1);

	/* Add error vector s2 */
	polyveck_add(&t1, &t1, &s2);

	/* Extract t1 and write public key */
	polyveck_caddq(&t1);
	polyveck_power2round(&t1, &t0, &t1);
	pack_pk(pk, rho, &t1);
	
	return 1;
}

bool dilithiumSign(uint8_t *sm, uint8_t *m, const uint8_t *sk, uint8_t *salt)
{
	unsigned int n;
	uint8_t seedbuf[2*SEEDBYTES + 3*CRHBYTES];
	uint8_t *rho, *tr, *key, *mu, *rhoprime;
	uint16_t nonce = 0;
	polyvecl mat[K], s1, y, z;
	polyveck t0, s2, w1, w0, h;
	poly cp;
	keccak_state state;

	//little-endian 8 byte
	uint64_t mlen = *((uint64_t*)m);
	m += 8;

	rho = seedbuf;
	tr = rho + SEEDBYTES;
	key = tr + CRHBYTES;
	mu = key + SEEDBYTES;
	rhoprime = mu + CRHBYTES;
	unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

	/* Compute CRH(tr, msg) */
	shake256_init(&state);
	shake256_absorb(&state, tr, CRHBYTES);
	shake256_absorb(&state, m, mlen);
	shake256_finalize(&state);
	shake256_squeeze(mu, CRHBYTES, &state);
	
	#ifdef DILITHIUM_RANDOMIZED_SIGNING
	// randombytes(rhoprime, CRHBYTES);
	memcpy(rhoprime, salt, CRHBYTES);
	#else
	crh(rhoprime, key, SEEDBYTES + CRHBYTES);
	#endif

	/* Expand matrix and transform vectors */
	polyvec_matrix_expand(mat, rho);
	polyvecl_ntt(&s1);
	polyveck_ntt(&s2);
	polyveck_ntt(&t0);

	rej:
	/* Sample intermediate vector y */
	polyvecl_uniform_gamma1(&y, rhoprime, nonce++);
	z = y;
	polyvecl_ntt(&z);

	/* Matrix-vector multiplication */
	polyvec_matrix_pointwise_montgomery(&w1, mat, &z);
	polyveck_reduce(&w1);
	polyveck_invntt_tomont(&w1);

	/* Decompose w and call the random oracle */
	polyveck_caddq(&w1);
	polyveck_decompose(&w1, &w0, &w1);
	polyveck_pack_w1(sm, &w1);

	shake256_init(&state);
	shake256_absorb(&state, mu, CRHBYTES);
	shake256_absorb(&state, sm, K*POLYW1_PACKEDBYTES);
	shake256_finalize(&state);
	shake256_squeeze(sm, SEEDBYTES, &state);
	poly_challenge(&cp, sm);
	poly_ntt(&cp);

	/* Compute z, reject if it reveals secret */
	polyvecl_pointwise_poly_montgomery(&z, &cp, &s1);
	polyvecl_invntt_tomont(&z);
	polyvecl_add(&z, &z, &y);
	polyvecl_reduce(&z);
	if(polyvecl_chknorm(&z, GAMMA1 - BETA))
	goto rej;

	/* Check that subtracting cs2 does not change high bits of w and low bits
	* do not reveal secret information */
	polyveck_pointwise_poly_montgomery(&h, &cp, &s2);
	polyveck_invntt_tomont(&h);
	polyveck_sub(&w0, &w0, &h);
	polyveck_reduce(&w0);
	if(polyveck_chknorm(&w0, GAMMA2 - BETA))
	goto rej;

	/* Compute hints for w1 */
	polyveck_pointwise_poly_montgomery(&h, &cp, &t0);
	polyveck_invntt_tomont(&h);
	polyveck_reduce(&h);
	if(polyveck_chknorm(&h, GAMMA2))
	goto rej;

	polyveck_add(&w0, &w0, &h);
	polyveck_caddq(&w0);
	n = polyveck_make_hint(&h, &w0, &w1);
	if(n > OMEGA)
	goto rej;

	/* Write signature */
	pack_sig(sm, sm, &z, &h);
	// *siglen = CRYPTO_BYTES;
	return 1;
}

bool dilithiumVerify(uint8_t *sm, uint8_t *m, const uint8_t *pk)
{
	unsigned int i;
	uint8_t buf[K*POLYW1_PACKEDBYTES];
	uint8_t rho[SEEDBYTES];
	uint8_t mu[CRHBYTES];
	uint8_t c[SEEDBYTES];
	uint8_t c2[SEEDBYTES];
	poly cp;
	polyvecl mat[K], z;
	polyveck t1, w1, h;
	keccak_state state;

	uint64_t mlen = *((uint64_t*)m);
	m += 8;

	// if(siglen != CRYPTO_BYTES)
	// return -1;

	unpack_pk(rho, &t1, pk);
	if(unpack_sig(c, &z, &h, sm))
	return -1;
	if(polyvecl_chknorm(&z, GAMMA1 - BETA))
	return -1;

	/* Compute CRH(CRH(rho, t1), msg) */
	crh(mu, pk, CRYPTO_PUBLICKEYBYTES);
	shake256_init(&state);
	shake256_absorb(&state, mu, CRHBYTES);
	shake256_absorb(&state, m, mlen);
	shake256_finalize(&state);
	shake256_squeeze(mu, CRHBYTES, &state);

	/* Matrix-vector multiplication; compute Az - c2^dt1 */
	poly_challenge(&cp, c);
	polyvec_matrix_expand(mat, rho);

	polyvecl_ntt(&z);
	polyvec_matrix_pointwise_montgomery(&w1, mat, &z);

	poly_ntt(&cp);
	polyveck_shiftl(&t1);
	polyveck_ntt(&t1);
	polyveck_pointwise_poly_montgomery(&t1, &cp, &t1);

	polyveck_sub(&w1, &w1, &t1);
	polyveck_reduce(&w1);
	polyveck_invntt_tomont(&w1);

	/* Reconstruct w1 */
	polyveck_caddq(&w1);
	polyveck_use_hint(&w1, &w1, &h);
	polyveck_pack_w1(buf, &w1);

	/* Call random oracle and verify challenge */
	shake256_init(&state);
	shake256_absorb(&state, mu, CRHBYTES);
	shake256_absorb(&state, buf, K*POLYW1_PACKEDBYTES);
	shake256_finalize(&state);
	shake256_squeeze(c2, SEEDBYTES, &state);
	for(i = 0; i < SEEDBYTES; ++i)
	if(c[i] != c2[i])
		return 0;

	return 1;
}


