import hashlib
import sys, os
sys.path.append("/home/Advancing-Blockchain-Based-Federated-Learning-Through-Verifiable-Off-Chain-Computations")

from pycrypto.zokrates_pycrypto.eddsa import PrivateKey, PublicKey
from pycrypto.zokrates_pycrypto.utils import write_signature_for_zokrates_cli

import pandas as pd
from Devices.utils.utils import read_yaml
from sklearn.preprocessing import StandardScaler
import numpy as np
import subprocess, json

class Encryption:

	def __init__(self, deviceName):
		self.sk = None
		self.pk = None
		self.deviceName = deviceName


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
		

	#Generate ZoKrates-friendly poseidon hash
	def poseidon_hash(self, data):
		def args_parser(args):
			res = ""
			for arg in range(len(args)):
				entry = args[arg]
				if isinstance(entry, (list, np.ndarray)):
					for i in range(len(entry)):
						row_i = entry[i]
						if isinstance(row_i, (list, np.ndarray)):
							for j in range(len(row_i)):
								val = row_i[j]
								res += str(val) + " "
						else:
							res += str(row_i) + " "
				else:
					res += str(args[arg]) + " "
			res = res[:-1]
			return res

		#For generating leaves
		base_path = "/home/Advancing-Blockchain-Based-Federated-Learning-Through-Verifiable-Off-Chain-Computations/Devices/Edge_Device/"
		if len(data) == 6:
			out_path = base_path + "poseidon/poseidon_leaf"
			abi_path = base_path + "poseidon/leaf.json"
			witness_path = base_path + "poseidon/leaf_witness_" + self.deviceName
			proof_path = base_path + "poseidon/leaf_proof_" + self.deviceName
			proving_key_path = base_path + "poseidon/leaf_proving.key"
			witness_args = args_parser(data).split(" ")
			
		elif len(data) == 2: 
			out_path = base_path + "poseidon/poseidon_tree"
			abi_path = base_path + "poseidon/tree.json"
			witness_path = base_path + "poseidon/tree_witness_" + self.deviceName
			proof_path = base_path + "poseidon/tree_proof_" + self.deviceName
			proving_key_path = base_path + "poseidon/tree_proving.key"
			witness_args = args_parser([int(data[0],16), int(data[1],16)]).split(" ")
		else:
			return

		zokrates = "zokrates"
		zokrates_compute_witness = [zokrates, "compute-witness", "-o", witness_path, '-i',out_path,'-s', abi_path, '-a']
		zokrates_compute_witness.extend(witness_args)
		g = subprocess.run(zokrates_compute_witness, capture_output=True)
		zokrates_generate_proof = [zokrates, "generate-proof",'-w',witness_path,'-p',proving_key_path,'-i',out_path,'-j',proof_path]
		g = subprocess.run(zokrates_generate_proof, capture_output=True)

		with open(proof_path,'r+') as f:
			proof=json.load(f)
			res = proof['inputs'][-1]

		return res[2:]


	#Hash data in batch with poseidon hash function (V2.0)
	def get_merkletree_poseidon(self, x, x_sign, y):
		data = []
		idx = 0
		for i in range(len(x)):
			for j in range(len(x[0])):
				data.append(x[i][j])

		for i in range(len(y)):
			data.append(y[i])

		if len(data)%6 != 0:
			nPadding = (int(len(data)/6) + 1) * 6 - len(data)
			for i in range(nPadding):
				data.append(0)

		#Generate leaf hashes
		merkletree = []
		for i in range(int(len(data)/6)):
			merkletree.append(self.poseidon_hash(data[i*6: i*6 + 6]))
			#print(int(str(self.poseidon_hash(data[i*6: i*6 + 6])),16))

		
		# #Construct the Merkle tree
		idx = 0
		nLeaf = len(merkletree)
		nSize = nLeaf
		while nLeaf > 1:
			for i in range(0, nLeaf, 2):
				nxtIDx = min(i+1, nLeaf-1)
				merkletree.append(self.poseidon_hash([merkletree[idx + i], merkletree[idx + nxtIDx]]))
				#print(int(str(self.poseidon_hash([merkletree[idx + i], merkletree[idx + nxtIDx]])), 16))
			idx += nLeaf
			nLeaf = int((nLeaf + 1)/2)

		# with open("./merkletree_py.txt", 'w') as f:
		# 	f.writelines(i.hex()+ '\n' for i in merkletree)
		return 0 if not merkletree else nSize, merkletree[-1], merkletree


	#Hash data in batch with sha256 hash function (V1.0)
	def get_merkletree_batch(self, x, x_sign, y):
		#Generate leaf hashes
		merkletree = []
		for i in range(len(x)):
			chunk = b''
			for j in range(len(x[0])):
				chunk += int.to_bytes(x[i][j], 32, "big")
			merkletree.append(self.hash_plain_data(chunk))
		
		chunk = b''
		for i in range(len(y)):
			chunk += int.to_bytes(int(y[i]), 32, "big")
		merkletree.append(self.hash_plain_data(chunk))

		'''
		#Add padding leaves to make the Merkle tree a balanced binary tree with leaves of powers of 2
		def isPowerOf2(n):
		    return (n&(n-1))==0

		def findNextPowerOf2(n):
		    n = n - 1
		    while n & n - 1:
		        n = n & n - 1       
		    return n << 1

		if not isPowerOf2(len(merkletree)):
			padding = 0
			for i in range(findNextPowerOf2(len(merkletree)) - len(merkletree)):
				merkletree.append(self.hash_plain_data(padding))
		'''

		#Construct the Merkle tree
		idx = 0
		nLeaf = len(merkletree)
		nSize = nLeaf
		while nLeaf > 1:
			for i in range(0, nLeaf, 2):
				nxtIDx = min(i+1, nLeaf-1)
				merkletree.append(self.hash_plain_data(merkletree[idx + i] + merkletree[idx + nxtIDx]))
			idx += nLeaf
			nLeaf = int((nLeaf + 1)/2)

		with open("./merkletree_py.txt", 'w') as f:
			f.writelines(i.hex()+ '\n' for i in merkletree)
		return 0 if not merkletree else nSize, merkletree[-1], merkletree

	#Hash entire data (V0.5)
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

	#Calculate the number of total hashes; the number needs to be specified in root.zok
	def calculate_total_hashes(self, nData:  int) -> int:
		if nData == 0:
			return 0
		elif nData == 1:
			return 1
		else:
			return nData + self.calculate_total_hashes(int(nData/2) if nData % 2 == 0 else int((nData + 1)/2))


	def get_merkleTree_depth(self, nData: int) -> int:
		return math.ceil(math.log2(nData))


#Getting args for zokrates cli when using merkle path
def write_args_for_zokrates_cli(pk, sig, msg, check_leaf, merkle_path, idx, path):
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
    args = args + " " + str(idx)

    # with open(path, "w+") as file:
    # 	for l in args:
    # 		file.write(l)

    return args

def write_args_for_zokrates_cli_poseidon(pk, sig, msg):
    "Writes the input arguments for verifyEddsa in the ZoKrates stdlib to file."
   
    sig_R, sig_S = sig
    #args = [sig_R.x, sig_R.y, sig_S, pk.p.x.n, pk.p.y.n]
    args = [sig_R.x, sig_R.y, sig_S, pk[0], pk[1]]
    args = " ".join(map(str, args))

    M0 = msg.hex()[:64]
    M1 = msg.hex()[64:]
    b0 = [str(int(M0[i:i+8], 16)) for i in range(0,len(M0), 8)]
    b1 = [str(int(M1[i:i+8], 16)) for i in range(0,len(M1), 8)]
    args = args + " " + " ".join(b0 + b1)

    return args

#Test purpose
def write_args_for_zokrates_cli_input(x, x_sign, y, pk, sig, msg):
	def args_parser(args):
		    res = ""
		    for arg in range(len(args)):
		        entry = args[arg]
		        if isinstance(entry, (list, np.ndarray)):
		            for i in range(len(entry)):
		                row_i = entry[i]
		                if isinstance(row_i, (list, np.ndarray)):
		                    for j in range(len(row_i)):
		                        val = row_i[j]
		                        res += str(val) + " "
		                else:
		                    res += str(row_i) + " "
		        else:
		            res += str(args[arg]) + " "
		    res = res[:-1]
		    return res

	args = " ".join(map(str, args_parser([x, x_sign, y]).split(" ")))
	print(" CHECKPOINT 1 ",args)
	sig_R, sig_S = sig
	args1 = [sig_R.x, sig_R.y, sig_S, pk.p.x.n, pk.p.y.n]
	#args = [sig_R.x, sig_R.y, sig_S, pk[0], pk[1]]
	args = args + " " +  " ".join(map(str, args1))
	

	M0 = msg.hex()[:64]
	M1 = msg.hex()[64:]
	b0 = [str(int(M0[i:i+8], 16)) for i in range(0,len(M0), 8)]
	b1 = [str(int(M1[i:i+8], 16)) for i in range(0,len(M1), 8)]
	args = args + " " + " ".join(b0 + b1)

	print(args)
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
	x_test = x_test.sample(40)
	y_test = y_test.sample(40)
	x_test = x_test.to_numpy()
	y_test = y_test.to_numpy()
	scaler.fit(x_test)
	x_test=scaler.transform(x_test)
	x_test = x_test * 10000
	x_test = x_test.astype(int)
	x , x_sign = convert_matrix(x_test)
	y_test = np.array(y_test)

	
	auth = Encryption()
	auth.generate_key_pair()
	#nLeaf, merkleRoot, merkleTree = auth.get_merkletree_batch(x, x_sign, y_test)
	# idx = 0
	# merklePath = auth.calculate_merkle_path(idx, merkleTree, nLeaf)
	nLeaf, merkleRoot, merkleTree = auth.get_merkletree_poseidon(x, x_sign, y_test)
	print("total hashes", auth.calculate_total_hashes(nLeaf))
	padding = bytes(32)
	padded_512_msg = bytes.fromhex(merkleRoot) + padding
	signature = auth.get_signature(padded_512_msg)
	write_args_for_zokrates_cli_input(x, x_sign, y_test, auth.pk, signature, padded_512_msg)
	#write_args_for_zokrates_cli(auth.pk, signature, padded_512_msg, merkleTree[idx], merklePath, idx, "./zokrates_input.txt")



if __name__ == '__main__':
	main()



	
