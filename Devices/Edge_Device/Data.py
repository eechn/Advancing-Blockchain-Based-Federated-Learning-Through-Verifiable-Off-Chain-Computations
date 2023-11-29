import os, sys
sys.path.append("/Users/chaehyeon/Documents/DPNM/2023/TUB/Advancing-Blockchain-Based-Federated-Learning-Through-Verifiable-Off-Chain-Computations")

from Devices.Edge_Device.Encryption import Encryption
import numpy as np
import pandas as pd
from Devices.utils.utils import read_yaml
import json
import subprocess
import requests
from Devices.MiddleWare.BlockChainClient import BlockChainConnection
#import hashlib


class Data:
    def __init__(self, blockchain_connection, deviceName, accountNR, configFile):
        self.curr_batch = None
        self.config = configFile
        self.batchSize = None
        self.blockChainConnection=blockchain_connection
        self.auth = Encryption(deviceName)
        self._init_for_data_authenticity()
        self.vc = None
        self.proof = None
        self.deviceName = deviceName
        self.accountNR = accountNR

    def set_batchSize(self,batchSize):
        self.batchSize=batchSize

    def generate_batch(self):
        self.curr_batch.dropna(inplace=True)
        batch=self.curr_batch.sample(self.batchSize)
        x_train = batch.drop(columns=self.config["DEFAULT"]["ResponseVariable"])
        y_train = batch[self.config["DEFAULT"]["ResponseVariable"]]
        x_train = x_train.to_numpy()
        y_train = y_train.to_numpy()
        return x_train, y_train
    
    def add_data_to_current_batch(self,data):
        if self.curr_batch is None:
            self.curr_batch = data
        else:
            self.curr_batch=pd.concat([self.curr_batch,data])
    
    def convert_matrix(self, m):
        max_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617
        m=np.array(m)
        return np.where(m < 0, max_field + m, m), np.where(m > 0, 0, 1)
    
    def _init_for_data_authenticity(self):
        self.auth.generate_key_pair()
        pk = []
        pk.extend([self.auth.pk.p.x.n, self.auth.pk.p.y.n])
        
    def get_vc(self):
        pk_x = self.auth.pk.p.x.n
        pk_y = self.auth.pk.p.y.n
        url = "http://127.0.0.1:5000/vc/" + str(pk_x) + "/" + str(pk_y)

        response = requests.get(url=url)
        self.vc = response.json()
    
        # pk, sig , msg = self.vc=json.load()
        # print(len(self.proof['inputs']))
        # return self.write_args_for_zokrates_cli_input(pk, sig, msg)
   
    def proving(self):
        signature = self.vc["vc"][0]["signature"]
        sig_R_x = signature['r']['x']
        sig_R_y = signature['r']['y']
        sig_S = signature['s']
        pubKey_CA = self.vc["vc"][0]["pubKey_CA"]

        # PubKey_device = int.to_bytes(self.auth.pk.p.x.n, 32, "big") + int.to_bytes(self.auth.pk.p.y.n, 32, "big")
        # testHash = hashlib.sha256(PubKey_device).digest()
        msg = self.vc["vc"][0]["deviceCertificate"]
        msg += msg

        args = [self.auth.pk.p.x.n, self.auth.pk.p.y.n, sig_R_x, sig_R_y, sig_S, pubKey_CA['x'], pubKey_CA['y']] 
        args = " ".join(map(str, args))
        M0 = msg[:64]
        M1 = msg[64:]
        b0 = [str(int(M0[i:i+8], 16)) for i in range(0,len(M0), 8)]
        b1 = [str(int(M1[i:i+8], 16)) for i in range(0,len(M1), 8)]

        args = args + " " + " ".join(b0 + b1)
  

        zokrates = "zokrates"
        zok_path = self.config["Registration"]["ZokratesPath"]
        zokrates_path = zok_path + 'root.zok'
        out_path=zok_path+"out"
        abi_path = zok_path+"abi.json"
        witness_path= zok_path + "witness_" + self.deviceName
        proof_path=zok_path+"proof_" + self.deviceName
        proving_key_path=zok_path+"proving.key"

        #Compute witness
        zokrates_compute_witness = [zokrates, "compute-witness", "-o", witness_path, '-i',out_path,'-s', abi_path, '-a']
        zokrates_compute_witness.extend(args.split(" "))
        g = subprocess.run(zokrates_compute_witness, capture_output=True)
  
        #Proof generation
        zokrates_generate_proof = [zokrates, "generate-proof",'-w', witness_path,'-p', proving_key_path, '-i', out_path, '-j', proof_path]
        g = subprocess.run(zokrates_generate_proof, capture_output=True)

        # with open(proof_path,'r+') as f:
        #     self.proof=json.load(f)
        #     print(self.proof)


    def verification(self):

        zok_path = self.config["Registration"]["ZokratesPath"]
        proof_path=zok_path+"proof_" + self.deviceName
        with open(proof_path,'r+') as f:
            self.proof=json.load(f)

        #Get generated DH(Device Handle)
        dh = self.proof['inputs'][-8:]
        commitment =""
        for i in range(len(dh)):
            commitment +=dh[i][-8:]


        self.blockChainConnection.verify_Registration(self.accountNR, commitment, self.proof)

        #self.blockChainConnection.setCommitment(self.accountNR, args)
       
    
    def get_Commitment(self):
        commitment = self.blockChainConnection.getCommitment(self.accountNR)
        return commitment
        
def write_args_for_zokrates_cli(pk, sig, msg, commitment):
    sig_R, sig_S = sig
    args = [sig_R.x, sig_R.y, sig_S, pk.p.x.n, pk.p.y.n]
    #args = [sig_R.x, sig_R.y, sig_S, pk[0], pk[1]]
    args = " ".join(map(str, args))
    

    M0 = msg.hex()[:64]
    M1 = msg.hex()[64:]
    b0 = [str(int(M0[i:i+8], 16)) for i in range(0,len(M0), 8)]
    b1 = [str(int(M1[i:i+8], 16)) for i in range(0,len(M1), 8)]
    b3 = [str(int(commitment[i:i+8], 16)) for i in range(0,len(M1), 8)]
    args = args + " " + " ".join(b0 + b1 + b3)
    return args

# def write_args_for_zokrates_cli(x, x_sign, y, pk, sig, msg, commitment):
#     def args_parser(args):
#         res = ""
#         for arg in range(len(args)):
#             entry = args[arg]
#             if isinstance(entry, (list, np.ndarray)):
#                 for i in range(len(entry)):
#                     row_i = entry[i]
#                     if isinstance(row_i, (list, np.ndarray)):
#                         for j in range(len(row_i)):
#                             val = row_i[j]
#                             res += str(val) + " "
#                     else:
#                         res += str(row_i) + " "
#             else:
#                 res += str(args[arg]) + " "
#         res = res[:-1]
#         return res

#     args = " ".join(map(str, args_parser([x, x_sign, y]).split(" ")))

#     sig_R, sig_S = sig
#     args1 = [sig_R.x, sig_R.y, sig_S, pk.p.x.n, pk.p.y.n]
#     #args = [sig_R.x, sig_R.y, sig_S, pk[0], pk[1]]
#     args = args + " " +  " ".join(map(str, args1))


#     M0 = msg.hex()[:64]
#     M1 = msg.hex()[64:]
#     b0 = [str(int(M0[i:i+8], 16)) for i in range(0,len(M0), 8)]
#     b1 = [str(int(M1[i:i+8], 16)) for i in range(0,len(M1), 8)]
#     b3 = [str(int(commitment[i:i+8], 16)) for i in range(0,len(M1), 8)]
#     print(f"Commitment to zok: {commitment}\n")
#     print(f"Commitment to b3: {b3}\n")
#     args = args + " " + " ".join(b0 + b1 + b3)
   

#     print(args)
#     return args



if __name__ == '__main__':
    config_file = read_yaml("/Users/chaehyeon/Documents/DPNM/2023/TUB/Advancing-Blockchain-Based-Federated-Learning-Through-Verifiable-Off-Chain-Computations/CONFIG.yaml")
    blockchain_connection=BlockChainConnection(config_file=config_file)
    blockchain_connection.connect()
    blockchain_connection.init_contract(0)
    test = Data(blockchain_connection, "1", 0, config_file)
    test.get_vc()
    test.proving()
    test.verification()