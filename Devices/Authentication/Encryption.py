import hashlib
import sys, os
sys.path.append("/Users/chaehyeon/Documents/DPNM/2023/TUB/Advancing-Blockchain-Based-Federated-Learning-Through-Verifiable-Off-Chain-Computations")

from pycrypto.zokrates_pycrypto.eddsa import PrivateKey, PublicKey
from pycrypto.zokrates_pycrypto.utils import write_signature_for_zokrates_cli

import pandas as pd
from Devices.utils.utils import read_yaml
from sklearn.preprocessing import StandardScaler
import numpy as np

class Encryption:

	def __init__(self):
		self.sk = None
		self.pk = None


	def generate_key_pair(self):
		self.sk = PrivateKey.from_rand()
		self.pk = PublicKey.from_private(self.sk)

		
	def hash_plain_data(self, plain: bytes) -> bytes:
		if isinstance(plain, pd.DataFrame):
			hashedData = hashlib.sha256(plain.values.tobytes()).digest()
		elif isinstance(plain, int):
			hashedData = hashlib.sha256(int.to_bytes(plain, 64, "big")).digest()
		else:
			hashedData = hashlib.sha256(plain).digest()
		return hashedData


	def get_signature(self, hashedData: bytes):
		signature = self.sk.sign(hashedData)
		return signature


	def verify(self, signature, inputData):
		is_verified = self.pk.verify(signature, inputData)
		return is_verified


	def generate_signature_for_zokrates_cli(self, pk, sig, msg, path):
		#path = 'zokrates_inputs.txt'
		write_signature_for_zokrates_cli(pk, sig, msg, path)


	def get_merkletree(self, original_data):
	    #Generate leaf hashes
	    merkletree = []
	    for data in original_data:
	    	for leaf in data:
	    		merkletree.append(self.hash_plain_data(leaf))


	    #Construct the Merkle tree
	    idx = 0
	    nHash = len(merkletree)
	    while nHash > 1:
	    	for i in range(0, nHash, 2):
	    		nxtIDx = min(i+1, nHash-1)
	    		merkletree.append(self.hash_plain_data(merkletree[idx + i] + merkletree[idx + nxtIDx]))
	    	idx += nHash
	    	nHash = int((nHash + 1)/2)

	    # with open("./merkletree_py.txt", 'w') as f:
	    # 	f.writelines(i.hex()+ '\n' for i in merkletree)
	    return 0 if not merkletree else merkletree[-1], merkletree


	def calculate_merkle_path(self, n_index, merkle_tree, nSize):
	    path = []
	    j = 0
	    while nSize > 1:
	        i = min(n_index ^ 1, nSize - 1)  
	        path.append({
	            'hash': merkle_tree[j+i],
	            'position': 1 if n_index % 2 == 1 else 0,
	            'idx' : j+i
	        })
	        n_index >>= 1
	        j += nSize
	        nSize = (nSize + 1) // 2

	    # for step in path:
    	# 	print(f"Hash: {step['hash']}, Position: {step['position']}, Position: {step['idx']}")
	    return path


	def calculate_total_hashes(self, nData:  int) -> int:
		if nData == 0:
			return 0
		elif nData == 1:
			return 1
		else:
			return nData + calculate_total_hashes(int(nData/2) if nData % 2 == 0 else int((nData + 1)/2))


	def get_merkleTree_depth(self, nData: int) -> int:
		return math.ceil(math.log2(nData))


#def write_signature_for_zokrates_cli(pk, sig, msg, data, path):
def write_args_for_zokrates_cli(pk, sig, msg, check_leaf, merkle_path, path):
    "Writes the input arguments for verifyEddsa in the ZoKrates stdlib to file."
    sig_R, sig_S = sig
    args = [sig_R.x, sig_R.y, sig_S, pk[0], pk[1]]
    args = " ".join(map(str, args))
   
    M0 = msg.hex()[:64] #merkleRoot
    M1 = msg.hex()[64:]
    b0 = [str(int(M0[i:i+8], 16)) for i in range(0,len(M0), 8)]
    b1 = [str(int(M1[i:i+8], 16)) for i in range(0,len(M1), 8)]
    args = args + " " + " ".join(b0 + b1)

    args = args + " " + " ".join([hash_to_u32(check_leaf)])   
    position = []    
    hashes = []
    for step in merkle_path:
    	position.append(str(step['position']))
    	hashes.append(hash_to_u32(step['hash']))

  
    args = args + " " + " ".join(position + hashes)


    with open(path, "w+") as file:
    	for l in args:
    		file.write(l)

    return args


def hash_to_u32(val: bytes) -> str:
    M0 = val.hex()[:128]
    b0 = [str(int(M0[i:i+8], 16)) for i in range(0,len(M0), 8)]
    return " ".join(b0)


def str_to_512bits(value: str) -> bytes:
    bin_str: int = int(''.join(format(i, '08b') for i in value.encode("utf-8")), base=2)
    padded_bytes: bytes = bin_str.to_bytes(64, "big")
    return padded_bytes


def bytes_to_u32(val: bytes) -> [int]:
    b0 = [str(int.from_bytes(val[i:i+4], "big")) for i in range(0,len(val), 4)]
    return " ".join(b0)

#Test data generation		
def convert_matrix(m):
	    max_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617
	    m=np.array(m)
	    return np.where(m < 0, max_field + m, m), np.where(m > 0, 0, 1)

def main():


	#Test purpose
	config_file = read_yaml("/Users/chaehyeon/Documents/DPNM/2023/TUB/Advancing-Blockchain-Based-Federated-Learning-Through-Verifiable-Off-Chain-Computations/CONFIG.yaml")
    
	datasource = config_file["DEFAULT"]["TestFilePath"]
	testdata = pd.read_csv(
	    datasource, names=
	    ["T_xacc", "T_yacc", "T_zacc", "T_xgyro", "T_ygyro", "T_zgyro", "T_xmag", "T_ymag", "T_zmag",
	     "RA_xacc", "RA_yacc", "RA_zacc", "RA_xgyro", "RA_ygyro", "RA_zgyro", "RA_xmag", "RA_ymag", "RA_zmag",
	     "LA_xacc", "LA_yacc", "LA_zacc", "LA_xgyro", "LA_ygyro", "LA_zgyro", "LA_xmag", "LA_ymag", "LA_zmag",
	     "RL_xacc", "RL_yacc", "RL_zacc", "RL_xgyro", "RL_ygyro", "RL_zgyro", "RL_xmag", "RL_ymag", "RL_zmag",
	     "LL_xacc", "LL_yacc", "LL_zacc", "LL_xgyro", "LL_ygyro", "LL_zgyro", "LL_xmag", "LL_ymag", "LL_zmag",
	     "Activity"]

	)
	testdata.fillna(inplace=True, method='backfill')
	testdata.dropna(inplace=True)
	testdata.drop(columns= ["T_xacc", "T_yacc", "T_zacc", "T_xgyro","T_ygyro","T_zgyro","T_xmag", "T_ymag", "T_zmag","RA_xacc", "RA_yacc", "RA_zacc", "RA_xgyro","RA_ygyro","RA_zgyro","RA_xmag", "RA_ymag", "RA_zmag","RL_xacc", "RL_yacc", "RL_zacc", "RL_xgyro","RL_ygyro","RL_zgyro" ,"RL_xmag", "RL_ymag", "RL_zmag","LL_xacc", "LL_yacc", "LL_zacc", "LL_xgyro","LL_ygyro","LL_zgyro" ,"LL_xmag", "LL_ymag", "LL_zmag"],inplace=True)
	activity_mapping = config_file["DEFAULT"]["ActivityMappings"]
	filtered_activities = config_file["DEFAULT"]["Activities"]
	activity_encoding = config_file["DEFAULT"]["ActivityEncoding"]
	for key in activity_mapping.keys():
	    testdata.loc[testdata['Activity'] == key,'Activity'] = activity_mapping[key]
	testdata = testdata[testdata['Activity'].isin(filtered_activities)]
	for key in activity_encoding.keys():
	    testdata.loc[testdata['Activity'] == key, 'Activity'] = activity_encoding[key]
	x_test = testdata.drop(columns="Activity")
	y_test = testdata["Activity"]


	scaler = StandardScaler()
	x_test = x_test.sample(10)
	x_test = x_test.to_numpy()
	scaler.fit(x_test)
	x_test=scaler.transform(x_test)
	x_test = x_test * 10000
	x_test = x_test.astype(int)
	x , x_sign = convert_matrix(x_test)

	
	auth = Encryption()
	auth.generate_key_pair()
	merkleRoot, merkleTree = auth.get_merkletree(x)

	idx = 0
	merklePath = auth.calculate_merkle_path(idx, merkleTree, 90)
	
	padding = bytes(32)
	padded_512_msg = merkleRoot + padding
	signature = auth.get_signature(padded_512_msg)
	write_args_for_zokrates_cli(auth.pk, signature, padded_512_msg, merkleTree[idx], merklePath)



if __name__ == '__main__':
	main()
    


	