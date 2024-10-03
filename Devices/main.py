import sys
import threading
import time
from MiddleWare.BlockChainClient import BlockChainConnection
#import sys, os
sys.path.append("/home/block/thesis_CHLEE/End-to-End-Verifiable-Decentralized-Federated-Learning")
#sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
from Devices.utils.utils import read_yaml
from Edge_Device.EdgeDevice import EdgeDevice
#+++++fix
from MiddleWare.Middleware import MiddleWare
#from Authentication.Authentication import MiddleWare

def start_Device(deviceName,accountNr,blockchain_connection,config_file):
    edgeDevice = EdgeDevice(deviceName, config_file=config_file)
    thread = threading.Thread(target=edgeDevice.start_EdgeDevice)
    thread.start()
    middleware = MiddleWare(blockchain_connection=blockchain_connection,deviceName=deviceName, accountNR=accountNr,configFile=config_file)
    middleware.start_Middleware()


if __name__ == '__main__':
    config_file = read_yaml("/home/block/thesis_CHLEE/End-to-End-Verifiable-Decentralized-Federated-Learning/CONFIG.yaml")
    blockchain_connection=BlockChainConnection(config_file=config_file)
    blockchain_connection.connect()
    for i in range(config_file["DEFAULT"]["NumberOfParticipants"]):
        thread=threading.Thread(target= start_Device,args=["Device_4",3,blockchain_connection,config_file])
        #thread=threading.Thread(target= start_Device,args=["Device_1",0,blockchain_connection,config_file])
        thread.start()
        time.sleep(1)

