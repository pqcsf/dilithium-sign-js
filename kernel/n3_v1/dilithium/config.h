#ifndef CONFIG_H
#define CONFIG_H

#if DILITHIUM_MODE == 2
#define CRYPTO_ALGNAME "Dilithium2"
#define DILITHIUM_NAMESPACE(s) pqcrystals_dilithium2_ref##s
#elif DILITHIUM_MODE == 3
#define CRYPTO_ALGNAME "Dilithium3"
#define DILITHIUM_NAMESPACE(s) pqcrystals_dilithium3_ref##s
#elif DILITHIUM_MODE == 5
#define CRYPTO_ALGNAME "Dilithium5"
#define DILITHIUM_NAMESPACE(s) pqcrystals_dilithium5_ref##s
#endif

#endif
