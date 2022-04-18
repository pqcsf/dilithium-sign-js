Dilithium Signature JS
===
The JS module of the post-quantum digital signature algorithm (Dilithium).

For more information about the Dilithium post-quantum digital signature algorithm, please refer to the following link: [Dilithium](https://pq-crystals.org/dilithium/)


Installation
---

##### from npm

	npm install dilithium-sign

##### from git

	git clone git@github.com:pqcsf/dilithium-sign-js.git
	cd dilithium-sign-js

Quick Start 
---

##### Dilithium2:

	const { getKernel } = require('dilithium-sign');
	(async () => 
	{
	    let Dilithium2 = await getKernel('dilithium2_n3_v1'); //get dilithium2_n3_v1 Kernel
	    //gernkey
	    let keypair = Dilithium2.genkey(); //return { sk, pk, genKeySeed }
	    //sign
	    let text = 'TEST MSG';
	    let sign = Dilithium2.sign(text, keypair.sk);
	    //verify
	    console.log(Dilithium2.verify(sign, text, keypair.pk));
	    //create public key by private key
	    let pk = Dilithium2.publicKeyCreate(keypair.sk);
	})();

##### Dilithium3:
Only the name of getKernel needs to be changed. (dilithium2_n3_v1 -> dilithium3_n3_v1)

	const { getKernel } = require('dilithium-sign');
	(async () => 
	{
	    let Dilithium3 = await getKernel('dilithium3_n3_v1'); //get dilithium2_n3_v1 Kernel
	    //gernkey
	    let keypair = Dilithium3.genkey(); //return { sk, pk, genKeySeed }
	    //sign
	    let text = 'TEST MSG';
	    let sign = Dilithium3.sign(text, keypair.sk);
	    //verify
	    console.log(Dilithium3.verify(sign, text, keypair.pk));
	    //create public key by private key
	    let pk = Dilithium3.publicKeyCreate(keypair.sk);
	})();

##### Use specific seeds to generate key pairs

	let seed = new Uint8Array(.....);
	let keypair = Dilithium2.genkey(seed);

Seed length according to: Dilithium2.genkeySeedByte, different algorithms may have different lengths.

##### Generate the same signature

	const salt = new Uint8Array(.....);
	let sign = Dilithium2R.sign(text, keypair.sk, salt);

Salt length according to: Dilithium2R.signSaltByte, different algorithms may have different lengths.
**Note: Only Dilithium2_R, Dilithium3_R, Dilithium5_R, Dilithium2_AES_R, Dilithium3_AES_R and Dilithium5_AES_R support salt setting**

API
---
The API is here: [API Reference](api.md)

License
---
The license is here: [License](LICENSE)

Author
---
- **PQCSF** (PQCSecondFoundation@gmail.com)



