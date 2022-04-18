const WasmBuf = require('./wasmBuf');
const { isUint8Array, uint8ArrayConcat, randomBytes } = require('./util.js');

const textEecoder = new TextEncoder("utf-8");

const algidPathTable = 
{
	dilithium2_n3_v1: '../kernel/n3_v1/wasmFile/dilithium2.js',
	dilithium3_n3_v1: '../kernel/n3_v1/wasmFile/dilithium3.js',
	dilithium5_n3_v1: '../kernel/n3_v1/wasmFile/dilithium5.js',

	dilithium2_AES_n3_v1: '../kernel/n3_v1/wasmFile/dilithium2-AES.js',
	dilithium3_AES_n3_v1: '../kernel/n3_v1/wasmFile/dilithium2-AES.js',
	dilithium5_AES_n3_v1: '../kernel/n3_v1/wasmFile/dilithium2-AES.js',

	dilithium2_R_n3_v1: '../kernel/n3_v1/wasmFile/dilithium2-R.js',
	dilithium3_R_n3_v1: '../kernel/n3_v1/wasmFile/dilithium3-R.js',
	dilithium5_R_n3_v1: '../kernel/n3_v1/wasmFile/dilithium5-R.js',

	dilithium2_AES_R_n3_v1: '../kernel/n3_v1/wasmFile/dilithium2-AES-R.js',
	dilithium3_AES_R_n3_v1: '../kernel/n3_v1/wasmFile/dilithium2-AES-R.js',
	dilithium5_AES_R_n3_v1: '../kernel/n3_v1/wasmFile/dilithium2-AES-R.js',
};

const saltRandomMode = 
[
	'dilithium2_R_n3_v1',
	'dilithium3_R_n3_v1',
	'dilithium5_R_n3_v1',
	'dilithium2_AES_R_n3_v1',
	'dilithium3_AES_R_n3_v1',
	'dilithium5_AES_R_n3_v1'
]

const kernelTable = {};

function api(kernel, algid)
{
	function signR(message, sk, salt = randomBytes(kernel._getCryptoSaltByte())) 
	{
		if(typeof message === 'string')
		{
			message = textEecoder.encode(message);
		}
		if(!isUint8Array(sk) || !isUint8Array(salt))
		{
			throw new Error('Parameter Error');
		}
		if(sk.length !== kernel._getSkByte())
		{
			throw new Error(`sk must be ${kernel._getSkByte()} bytes`);
		}
		if(salt.length !== kernel._getCryptoSaltByte())
		{
			throw new Error(`salt must be ${kernel._getCryptoSaltByte()} bytes`);
		}

		let wSign = new WasmBuf(kernel, kernel._getCryptoByte());
		let wSk = new WasmBuf(kernel, sk);
		let wSalt = new WasmBuf(kernel, salt);
		let msgLength = new Uint8Array(8);
		new DataView(msgLength.buffer).setBigUint64(0, BigInt(message.length), 1);
		let wMsg = new WasmBuf(kernel, uint8ArrayConcat([msgLength, message]));
		
		let result = kernel._sign(wSign.wasmBufPtr, wMsg.wasmBufPtr, wSk.wasmBufPtr, wSalt.wasmBufPtr);
		if(!result) 
		{
			wSign.free();
			wMsg.free();
			wSk.freeSafe();
			wSalt.freeSafe();
			return;
		}
		
		let signMsg = wSign.readJsBuf();
		wSign.free();
		wMsg.free();
		wSk.freeSafe();
		wSalt.freeSafe();
		return signMsg;
	}

	function sign(message, sk) 
	{
		if(typeof message === 'string')
		{
			message = textEecoder.encode(message);
		}
		if(!isUint8Array(sk))
		{
			throw new Error('Parameter Error');
		}
		if(sk.length !== kernel._getSkByte())
		{
			throw new Error(`sk must be ${kernel._getSkByte()} bytes`);
		}

		let wSign = new WasmBuf(kernel, kernel._getCryptoByte());
		let wSk = new WasmBuf(kernel, sk);
		let msgLength = new Uint8Array(8);
		new DataView(msgLength.buffer).setBigUint64(0, BigInt(message.length), 1);
		let wMsg = new WasmBuf(kernel, uint8ArrayConcat([msgLength, message]));
		
		let result = kernel._sign(wSign.wasmBufPtr, wMsg.wasmBufPtr, wSk.wasmBufPtr);
		if(!result) 
		{
			wSign.free();
			wMsg.free();
			wSk.freeSafe();
			return;
		}
		
		let signMsg = wSign.readJsBuf();
		wSign.free();
		wMsg.free();
		wSk.freeSafe();
		return signMsg;
	}

	return {

		genkey(genkeySeed = randomBytes(kernel._getGenKeySeedByte()))
		{
			if(!isUint8Array(genkeySeed))
			{
				throw new Error('Parameter Error');
			}
			if(genkeySeed.length !== kernel._getGenKeySeedByte())
			{
				throw new Error(`Seeds must be ${kernel._getGenKeySeedByte()} bytes`);
			}

			let wSeed = new WasmBuf(kernel, kernel._getGenKeySeedByte());
			let wPk = new WasmBuf(kernel, kernel._getPkByte());
			let wSk = new WasmBuf(kernel, kernel._getSkByte());
			wSeed.writeJsBuf(genkeySeed);

			let result = kernel._genkey(wSeed.wasmBufPtr, wPk.wasmBufPtr, wSk.wasmBufPtr);
			if(!result) 
			{
				wSeed.freeSafe();
				wPk.free();
				wSk.freeSafe();
				return;
			}

			let keypair =
			{
				genkeySeed, 
				pk: wPk.readJsBuf(), 
				sk: wSk.readJsBuf(), 
			}
			wSeed.freeSafe();
			wPk.free();
			wSk.freeSafe();
			return keypair
		},
		publicKeyCreate(sk)
		{
			if(!isUint8Array(sk))
			{
				throw new Error('Parameter Error');
			}
			if(sk.length !== kernel._getSkByte())
			{
				throw new Error(`sk must be ${kernel._getSkByte()} bytes`);
			}

			let wSk = new WasmBuf(kernel, sk);
			let wPk = new WasmBuf(kernel, kernel._getPkByte());
			let result = kernel._publicKeyCreate(wSk.wasmBufPtr, wPk.wasmBufPtr);
			if(!result) 
			{
				wPk.free();
				wSk.freeSafe();
				return;
			}

			let pk = wPk.readJsBuf();
			wPk.free();
			wSk.freeSafe();
			return pk;
		},
		sign: (saltRandomMode.includes(algid)) ? signR : sign,
		verify(signMsg, message, pk) 
		{
			if(typeof message === 'string')
			{
				message = textEecoder.encode(message);
			}
			if(!isUint8Array(signMsg) || !isUint8Array(pk))
			{
				throw new Error('Parameter Error');
			}
			if(signMsg.length > kernel._getCryptoByte())
			{
				throw new Error(`signMsg are limited to a maximum of ${kernel._getCryptoByte()} bytes`);
			}
			if(pk.length !== kernel._getPkByte())
			{
				throw new Error(`pk must be ${kernel._getPkByte()} bytes`);
			}

			let wSign = new WasmBuf(kernel, signMsg);
			let wPk = new WasmBuf(kernel, pk);
			let msgLength = new Uint8Array(8);
			new DataView(msgLength.buffer).setBigUint64(0, BigInt(message.length), 1);
			let wMsg = new WasmBuf(kernel, uint8ArrayConcat([msgLength, message]));

			let result = kernel._verify(wSign.wasmBufPtr, wMsg.wasmBufPtr, wPk.wasmBufPtr);
			wSign.free();
			wMsg.free();
			wPk.free();
			return (result) ? true : false ;
		},

		//--- Get Parameters ---
		algid,
		get genkeySeedByte(){ return kernel._getGenKeySeedByte(); 	},
		get skByte() 		{ return kernel._getPkByte(); 			},
		get pkByte()		{ return kernel._getPkByte(); 			},
		get signByte()		{ return kernel._getCryptoByte(); 		},
		get signSaltByte()	{ return kernel._getCryptoSaltByte(); 	},
		get signNonceByte()	{ return kernel._getCryptoNonceByte(); 	},
	}
}

function getKernel(algid)
{
	if(!kernelTable[algid]) 
	{
		if(!algidPathTable[algid]) 
		{
			return;
		}
		let kernel = require(algidPathTable[algid]);
		kernelTable[algid] = 
		{ 
			initCallback: [], 
			methood: api(kernel, algid),
			init: false
		};
		kernel.onRuntimeInitialized = () => 
		{
			kernelTable[algid].init = true;
			for(let i=0; i<kernelTable[algid].initCallback.length; i++) 
			{
				kernelTable[algid].initCallback[i](kernelTable[algid].methood);
			}
		};
	}
	if(!kernelTable[algid].init) 
	{	
		return new Promise((res) => 
		{
			kernelTable[algid].initCallback.push(res);
		});
	}
	return kernelTable[algid].methood;
}

const getKernelNameList = Object.keys(algidPathTable);

module.exports = { getKernel, getKernelNameList };