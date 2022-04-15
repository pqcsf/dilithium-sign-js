const { getKernel, util, getKernelNameList } = require('../index');

console.log(getKernelNameList);

(async () =>
{
	const dilithium = await getKernel('dilithium5R_n3_v1');
	if(!dilithium) 
	{
		return console.log('getKernel fail');
	}

	console.log(`------------------ genkey ------------------`);
	let key = dilithium.genkey();
	if(!key)
	{
		return console.log('genkey fail');
	}

	console.log(`------------------ genkeySeed (${key.genkeySeed.length}) ----------`);
	console.log(util.uint8ArrayToString(key.genkeySeed, 'base64'));
	console.log(`------------------ pk (${key.pk.length}) ------------------`);
	console.log(util.uint8ArrayToString(key.pk, 'base64'));
	console.log(`------------------ sk (${key.sk.length}) ------------------`);
	console.log(util.uint8ArrayToString(key.sk, 'base64'));

	let text = 'TEST MSG';
	let sign = dilithium.sign(text, key.sk);
	if(!sign) return console.log('sign fail');
	console.log(`------------------ sign (${sign.length}) ------------------`);
	console.log(util.uint8ArrayToString(sign, 'base64'));
	console.log('------------------ verify ---------------');
	console.log(dilithium.verify(sign, text, key.pk));

	let pk = dilithium.publicKeyCreate(key.sk);
	console.log(`------------------ create pk (${pk.length}) ------------------`);
	console.log(util.uint8ArrayToString(pk, 'base64'));
	console.log(`------------------ pk eq ------------------`);
	console.log(util.uint8ArrayEqual(pk, key.pk));

	let key2 = dilithium.genkey(key.genkeySeed);
	console.log(`------------------ create sk (${key2.sk.length}) ------------------`);
	console.log(util.uint8ArrayToString(key2.sk, 'base64'));
	console.log(`------------------ sk eq ------------------`);
	console.log(util.uint8ArrayEqual(key.sk, key2.sk));

	console.log(`------------------ const sign eq ------------------`);
	let constSalt = util.randomBytes(dilithium.signSaltByte);
	let constSign1 = dilithium.sign(text, key.sk, constSalt);
	let constSign2 = dilithium.sign(text, key.sk, constSalt);
	console.log("constSign1 === constSign2 : ", util.uint8ArrayEqual(constSign1, constSign2));
	console.log("randomSign1 === constSign2 : ", util.uint8ArrayEqual(sign, constSign2));
})();
