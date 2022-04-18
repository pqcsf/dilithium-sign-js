API Reference
---

For compatibility with mainstream browsers, the parameters of the functions are Uint8Array instead of Buffer (Nodejs).

The main API consists of three entry points:

	const { getKernel, getKernelNameList, util } = require('dilithium-sign');

#### `getKernel(algid: string): Promise<Kernel>`
Acquisition of core modules for algorithms, The available algorithms are:

1. dilithium2_n3_v1
2. dilithium3_n3_v1
3. dilithium5_n3_v1
4. dilithium2_AES_n3_v1
5. dilithium3_AES_n3_v1
6. dilithium5_AES_n3_v1
7. dilithium2_R_n3_v1
8. dilithium3_R_n3_v1
9. dilithium5_R_n3_v1
10. dilithium2_AES_R_n3_v1
11. dilithium3_AES_R_n3_v1
12. dilithium5_AES_R_n3_v1

#### `getKernelNameList(): string[]`
Get a list of supported algorithm names

#### `util: object`
Some common utility programs

Kernel
---
### The kernel is the interface to the algorithm and contains the following methods.

	const Kernel = await getKernel('dilithium2_n3_v1');

#### `Kernel.genkey(genkeySeed?: Uint8Array): { genkeySeed: Uint8Array, pk: Uint8Array, sk: Uint8Array } | undefined`
Generate key pair, if the input genkeySeed is not empty, then use genkeySeed to generate key pair, otherwise use random genkeySeed to generate it.

#### `Kernel.publicKeyCreate(sk: Uint8Array): Uint8Array | undefined`
Generate public key using private key

#### `Kernel.sign(message: Uint8Array | string, sk: Uint8Array, salt?: Uint8Array)): Uint8Array | undefined`
Create a Dilithium signature. If the salt is empty, generate it randomly.

#### `Kernel.verify(signMsg: Uint8Array, message: Uint8Array, pk: Uint8Array) : boolean`
Verify a Dilithium signature.

### There are also the following members.

#### `Kernel.algid`
Name of the algorithm

#### `Kernel.genkeySeedByte`
Number of bytes of key generation seeds.

#### `Kernel.skByte`
Number of private key bytes.

#### `Kernel.pkByte`
Number of public key bytes.

#### `Kernel.signByte`
Number of signature bytes.

#### `Kernel.signSaltByte`
Number of bytes of signature's random salt.

#### `Kernel.signNonceByte`
Number of bytes of signature's random nonce. It is part of the random salt.

util
---

#### `util.isUint8Array(data: any): boolean`

#### `util.isUint(data: any): boolean`

#### `util.uint8ArrayToString(buf: Uint8Array, decode: string = 'hex'): string`

#### `util.base64ToUint8Array(data: string): Uint8Array | undefined`

#### `util.hexStringToUint8Array(data: string): Uint8Array | undefined`

#### `util.uint8ArrayConcat(bufs: Uint8Array[]): Uint8Array`

#### `util.uint8ArrayWriteBigUInt64LE(buf: Uint8Array, ui64: BigInt, offset: number = 0): undefined`

#### `util.uint8ArrayReadBigUInt64LE(buf: Uint8Array, offset: number = 0): BigInt`

#### `util.uint8ArrayReadUint16BE(buf: Uint8Array, offset: number = 0): number`

#### `util.uint8ArrayEqual(buf1: Uint8Array, buf1: Uint8Array): boolean`

#### `util.randomBytes(size: number): Uint8Array`










