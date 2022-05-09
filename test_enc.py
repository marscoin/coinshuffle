from binascii import hexlify, unhexlify
import json
import Crypto
from Crypto.PublicKey import RSA
from base64 import b64decode

def encrypt(epkey, msg):
    return hexlify(RSA.importKey(unhexlify(str(epkey))).encrypt(str(msg), 'x')[0])

order = {'0': '30819f300d06092a864886f70d010101050003818d0030818902818100ad6a218c912a102af6677bf6f772beeeb629056e7e88e41ca6896d8c8cb98ad062406a6fca43884e78a7f5785390b6a0b8555689ada0e533fed3af1f35a424248746bff4744379041105366f1199909cad1e3e42ba9da082925c9f35c78e7e6c8d60fd89b742ca6ae8de1cea35453acbcb0bf281f9ce382fd43f06463795df950203010001', '1': '30819f300d06092a864886f70d010101050003818d0030818902818100d0c98b617bbd9a086755d73d7a4b71c842c1214d196339091802c3056e4f4dc080e779b9ea121b9310deab999894bc2a75f05574364073152267f2f756c97600f4b291f4042a7a4614544e5787d423e33a6a76c872fe1c0d2f07c16b2eb018cf64a361b7c51000ad9a3c5f511621801889e097509f74a8121435e9d540b7360f0203010001', '2': '30819f300d06092a864886f70d010101050003818d00308189028181009021ae4f2d655e6e705e7a188a5579c39f9d09f5558dac01462b82457c727845f3b018520dcf0d1ebb36c708cfef7de4735c83c1df6ff280cab814cadbb9d044303f3ec3c71788858cc28f262674dffbe554e87221d144ed0bcd62e296f63e926380d337d603525984cbb1b94de26477dbf6988fc0c6bd7776e0dd3245c02aff0203010001', '3': '30819f300d06092a864886f70d010101050003818d00308189028181009a6c2f3a7fbd98378b6ece1faa3c76b28de3f744d50029b1dfd47b5747d4983ac3d28e14dc673d7d37f5fdd85921e48475b03ad276f8b53e06d9996369858dea0e095184b16b3a3d320c821a8f8b2c4de0b4732b6efb1ff4e35bd2ab9390767b50882f2a72fea8cc118d76abd6d0ede2b849b617370d09c5549cc98bd7ec40c90203010001', '4': '30819f300d06092a864886f70d010101050003818d0030818902818100df22ce49838448458814f52d9ac3f22f16785a4587b87d9f857861af2c08796cf5f56d89e89207d43d12b04e7ece3bf27d818812aaa6838b19226ee301bc845807034578a092cb695bd1adf0eb64977a2a47517c495e8a072883469136d8ca0273f8d477aed0307355cdd8cf394e3b01cfb54eb999fc8e70666e7863f54207ed0203010001', '5': '30819f300d06092a864886f70d010101050003818d0030818902818100a1ee9cf32ab9d42aa689dd58dfc11c2e4847c141680e81538e539e8b5c25c0085b220fcf5762cd7ecaa5ee973023980a0e7d0f5269ba4ff8af6f051cffc8cf3a44f11a3aba1f59ad3452fee2e3c305a33cc2c956d24d8639df3f6ad593c1f3c88566a2930215c7b0c9ebb1d023ca71e90d5bc09b70c8c880779cc864c3f668210203010001'}  
 
t = "BobPrime"
for i in range(5,-1,-1):
	print(t)
	t = encrypt(order[str(i)], t) 
