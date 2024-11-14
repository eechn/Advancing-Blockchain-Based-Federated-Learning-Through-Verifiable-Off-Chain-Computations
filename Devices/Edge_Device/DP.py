
import os, sys
sys.path.append("/home/dpnm/thesis_CHLEE/End-to-End-Verifiable-Decentralized-Federated-Learning")
from Devices.Edge_Device.Encryption import Encryption
from Devices.Edge_Device.Data import Data
import numpy as np
import math
from Devices.utils.utils import read_yaml

config_file = read_yaml("/home/dpnm/thesis_CHLEE/End-to-End-Verifiable-Decentralized-Federated-Learning/CONFIG.yaml")


#BLock hash = 0x80feb367812ae0f689b0fbf8143dd81360a04cd7cc2adc9b5c4fd918c2a75097
#Merkle Root = 2a29e728b0e901d09b14da6643f5e10d11abbfeaad001a48835dbf8f46edb2a3

a = [3912023,3218876,2813411,2525729,2302585,2120264,1966113,1832581,1714798,1609438,1514128,1427116,1347074,1272966,1203973,1139434,1078810,1021651,967584,916291,867501,820981,776529,733969,693147,653926,616186,579818,544727,510826,478036,446287,415515,385662,356675,328504,301105,274437,248461,223144,198451,174353,150823,127833,105361,83382,61875,40822,20203,0,20203,40822,61875,83382,105361,127833,150823,174353,198451,223144,248461,274437,301105,328504,356675,385662,415515,446287,478036,510826,544727,579818,616186,653926,693147,733969,776529,820981,867501,916291,967584,1021651,1078810,1139434,1203973,1272966,1347074,1427116,1514128,1609438,1714798,1832581,1966113,2120264,2302585,2525729,2813411,3218876,3912023]
b =[-39120.23005428146, -32188.758248682007, -28134.107167600363, -25257.286443082558, -23025.850929940454, -21202.63536200091, -19661.12856372833, -18325.8146374831, -17147.984280919267, -16094.379124341003, -15141.277326297755, -14271.163556401458, -13470.736479666091, -12729.656758128873, -12039.728043259362, -11394.342831883649, -10788.096613719297, -10216.512475319814, -9675.840262617055, -9162.90731874155, -8675.005677047231, -8209.805520698303, -7765.287894989963, -7339.691750802004, -6931.471805599453, -6539.26467406664, -6161.86139423817, -5798.18495252942, -5447.271754416722, -5108.256237659907, -4780.358009429998, -4462.871026284195, -4155.154439616658, -3856.6248081198464, -3566.7494393873244, -3285.040669720361, -3011.050927839216, -2744.368457017603, -2484.613592984996, -2231.435513142097, -1984.5093872383832, -1743.533871447778, -1508.2288973458367, -1278.3337150988489, -1053.6051565782627, -833.8160893905101, -618.7540371808753, -408.2199452025517, -202.02707317519466, -0.0, 202.02707317519466, 408.2199452025517, 618.7540371808753, 833.8160893905114, 1053.605156578264, 1278.3337150988502, 1508.228897345835, 1743.5338714477766, 1984.5093872383818, 2231.435513142097, 2484.613592984996, 2744.368457017603, 3011.050927839216, 3285.040669720361, 3566.7494393873244, 3856.624808119848, 4155.154439616659, 4462.871026284196, 4780.358009429996, 5108.256237659905, 5447.271754416719, 5798.18495252942, 6161.86139423817, 6539.26467406664, 6931.471805599453, 7339.691750802004, 7765.287894989964, 8209.805520698303, 8675.005677047233, 9162.907318741552, 9675.84026261706, 10216.51247531981, 10788.096613719297, 11394.342831883647, 12039.72804325936, 12729.656758128873, 13470.736479666091, 14271.163556401458, 15141.277326297757, 16094.379124341005, 17147.98428091927, 18325.814637483105, 19661.128563728333, 21202.6353620009, 23025.85092994045, 25257.286443082547, 28134.107167600356, 32188.758248681996, 39120.23005428145]

LAPLACE = 100

def getEntropy(BC_entropy, merkleRoot, DeviceName):
    Enc = Encryption(DeviceName)
    seed = Enc.poseidon_hash([BC_entropy[2:], merkleRoot])
    BChash = int(BC_entropy[2:], 16)
    Mk = int(merkleRoot, 16)
    msg = bytes.fromhex(seed)
    M0 = msg.hex()[:64]

    seeds = []
    for i in range(0, 64, 8):
        seeds.append(M0[i:i+8])
    
    P_candidates = []
    for chunck in seeds:
        seed = Enc.poseidon_hash([chunck, BC_entropy[2:]])
        msg = bytes.fromhex(seed)
        M0 = msg.hex()[:64]
        for i in range(0, 64, 8):
            P_candidates.append(M0[i:i+8])
    

    print(P_candidates)
    p = []
    for P_candidate in P_candidates:
        p.append(hex(int(P_candidate, 16) % 99))
    

    b0 = [str(int(M0[i:i+8], 16)) for i in range(0,len(M0), 8)]

    args = " ".join([str(BChash), str(Mk)] +b0)

    return p


#def getRandomNumber(p):

def getNoise(p, Lap):
    noise = []
    for i in p:
        noise.append(Lap[int(i, 16)]) 
    return noise

def getNoise_sign(p, Lap, Lap_sign):
    noise = []
    noise_sign = []
    for i in p:
        noise.append(Lap[int(i, 16)])
        noise_sign.append(Lap_sign[int(i, 16)])
    
    return noise, noise_sign

def deterministic_laplace(epsilon, sensitivity):
    #epsilon = 1.0
    #sensitivity = config_file["DEFAULT"]["Precision"]
    scale = sensitivity / epsilon

    Lap = []
    for i in range(1, 100):
        if i/100 < 0.5 :
            Lap.append(scale * math.log(2 * i/100))
        else:
            Lap.append(-(scale * math.log(2 * (1-i/100))))
    
    for i in range(0, 99):
        Lap[i] = round(Lap[i])   
    
    return Lap


def load_data(file_path):
    with open(file_path, 'r') as file:
        data = file.read().strip().split(',')
    # 문자열 데이터를 float 타입으로 변환
    return [float(x) for x in data]

def calculate_statistics(data):
    max_value = np.max(data)
    min_value = np.min(data)
    mean_value = np.mean(data)
    std_dev = np.std(data)
    
    return {
        'Maximum': max_value,
        'Minimum': min_value,
        'Mean': mean_value,
        'Standard Deviation': std_dev
    }

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
if __name__ == "__main__":
    '''
    file_path = config_file["DEFAULT"]["TestFilePath"]
    data = load_data(file_path)

    # 통계값 계산
    statistics = calculate_statistics(data)

    # 통계값 출력
    for stat_name, stat_value in statistics.items():
        print(f'{stat_name}: {stat_value}')
    '''

    p = getEntropy("0x80feb367812ae0f689b0fbf8143dd81360a04cd7cc2adc9b5c4fd918c2a75097","2a29e728b0e901d09b14da6643f5e10d11abbfeaad001a48835dbf8f46edb2a3", "Device_1")
    #getLaplace()
    print(p)
    Lap = deterministic_laplace(100, config_file["DEFAULT"]["Precision"])
    print(Lap)
    Lap, Lap_sign = Data.convert_matrix(Lap)
    noise = getNoise(p, Lap)
    noise, noise_sign = getNoise_sign(p, Lap, Lap_sign)
    #print(args_parser(Lap))
    #print(args_parser(Lap_sign))
    #print(args_parser(noise))
    #print(args_parser(noise_sign))

    #p = getEntropy("0x80feb367812ae0f689b0fbf8143dd81360a04cd7cc2adc9b5c4fd918c2a75097","2a29e728b0e901d09b14da6643f5e10d11abbfeaad001a48835dbf8f46edb2a3")

