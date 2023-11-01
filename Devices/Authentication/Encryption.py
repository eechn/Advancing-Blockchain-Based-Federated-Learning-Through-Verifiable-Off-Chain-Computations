import hashlib
#from ecdsa import SigningKey

import sys, os
sys.path.append("/Users/chaehyeon/Documents/DPNM/2023/TUB/Advancing-Blockchain-Based-Federated-Learning-Through-Verifiable-Off-Chain-Computations")

from pycrypto.zokrates_pycrypto.eddsa import PrivateKey, PublicKey
from pycrypto.zokrates_pycrypto.field import FQ
from pycrypto.zokrates_pycrypto.utils import write_signature_for_zokrates_cli
import pandas as pd


class Encryption:

	def __init__(self):
		self.sk = None
		self.pk = None
		#self.hashedData = None
		self.signature = None
		# self.config=config_file
		# self.deviceName = deviceName
		
	def hash_plain_data(self, plain): 
		if isinstance(plain, pd.DataFrame):
		#hashedData = hashlib.sha512(plain.encode("utf-8")).digest()
			#hashedData = hashlib.sha512(plain.values.tobytes()).hexdigest()
			hashedData = hashlib.sha512(plain.values.tobytes()).digest()
		else:
			hashedData = hashlib.sha512(plain.encode("utf-8")).digest()
		return hashedData


	def generate_key_pair(self):
		#key = FQ(key_seed)
		#key = FQ(1997011358982923168928344992199991480689546837621580239342656433234255379025)
		#self.sk = PrivateKey(key)
		self.sk = PrivateKey.from_rand()
		self.pk = PublicKey.from_private(self.sk)


	def get_signature(self, hashedData):
		self.signature = self.sk.sign(hashedData)
		return self.signature

	def verify(self, signature, inputData):
		is_verified = self.pk.verify(signature, inputData)
		return is_verified

	def generate_signature_for_zokrates_cli(self, pk, sig, msg, path):
		#path = 'zokrates_inputs.txt'
		write_signature_for_zokrates_cli(pk, sig, msg, path)




def main():
	encrypt = Encryption()
	hdata = encrypt.hash_plain_data("plain message for test")
	test_data = encrypt.hash_plain_data("test data")
	encrypt.key_generation()
	print(encrypt.pk)
	print(encrypt.sk)
	encrypt.get_signature(hdata)
	print(type(encrypt.signature))
	print("Verified" if encrypt.verify(encrypt.signature, test_data) == True else "not verified")

	path = 'zokrates_inputs.txt'
	write_signature_for_zokrates_cli(encrypt.pk, encrypt.signature, hdata, path)


if __name__ == '__main__':
	main()

	