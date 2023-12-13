import os.path, sys

import pandas as pd

sys.path.append("/Users/chaehyeon/Documents/DPNM/2023/TUB/Advancing-Blockchain-Based-Federated-Learning-Through-Verifiable-Off-Chain-Computations")
from Devices.utils.utils import read_yaml


class Analytics:
    def __init__(self,deviceName,config_file):
        self.config=config_file
        self.deviceName=deviceName
        self.round_time=pd.DataFrame()
        self.round_gas = pd.DataFrame()
        self.round_proof_times = pd.DataFrame()
        self.round_training_local_time=pd.DataFrame()
        self.round_update_blockchain_time=pd.DataFrame()
        self.round_score=pd.DataFrame()
        self.round_classification_report=pd.DataFrame()
        self.round_witness_time=pd.DataFrame()
        self.round_proof_time=pd.DataFrame()
        self.round_witness_size=pd.DataFrame()
        self.round_proof_size=pd.DataFrame()


    def add_round_time(self,round,time):
        df=pd.DataFrame([{'Round-Number':round,'Time-Taken':time}])
        self.round_time=pd.concat([self.round_time,df])

    def add_round_update_blockchain_time(self,round,time):
        df=pd.DataFrame([{'Round-Number':round,'Time-Taken':time}])
        self.round_update_blockchain_time=pd.concat([self.round_update_blockchain_time,df])

    def add_round_gas(self,round,gas):
        df=pd.DataFrame([{'Round-Number':round,'Gas-Costs':gas}])
        self.round_gas=pd.concat([self.round_gas,df])

    def add_round_proof_times(self,round,time):
        df=pd.DataFrame([{'Round-Number':round,'Time-Taken':time}])
        self.round_proof_times=pd.concat([self.round_proof_times,df])

    def add_round_training_local_time(self,round,time):
        df=pd.DataFrame([{'Round-Number':round,'Time-Taken':time}])
        self.round_training_local_time=pd.concat([self.round_training_local_time,df])

    def add_round_score(self,round,score):
        df=pd.DataFrame([{'Round-Number':round,'Score':score}])
        self.round_score=pd.concat([self.round_score,df])

    def add_round_classification_report(self, round, report):
        targets=self.config["DEFAULT"]["ActivitiesEncoded"]
        dic={'Round-Number': round}
        for target in targets:
            dic[target] = report[str(target)]['precision']
        df = pd.DataFrame([dic])
        self.round_classification_report = pd.concat([self.round_classification_report, df])
    
    def add_round_witness_time(self, round, time):
        df=pd.DataFrame([{'Round-Number':round,'Time-Taken':time}])
        self.round_witness_time=pd.concat([self.round_witness_time,df])

    def add_round_proof_time(self, round, time):
        df=pd.DataFrame([{'Round-Number':round,'Time-Taken':time}])
        self.round_proof_time=pd.concat([self.round_proof_time,df])

    def add_round_witness_size(self, round, size):
        df=pd.DataFrame([{'Round-Number':round,'Size':size}])
        self.round_witness_size=pd.concat([self.round_witness_size,df])

    def add_round_proof_size(self, round, size):
        df=pd.DataFrame([{'Round-Number':round,'Size':size}])
        self.round_proof_size=pd.concat([self.round_proof_size,df])

    def write_data(self):
        base_path=self.config["DEFAULT"]["AnalyticsOutBase"]
        path = os.path.join(os.path.join(os.path.join(base_path,"NumberOfParticipants_"+str(self.config["DEFAULT"]["NumberOfParticipants"])),"BatchSize_"+str(self.config["DEFAULT"]["BatchSize"])),self.deviceName)
        if not os.path.exists(path):
            os.makedirs(path)
        self.round_time.to_csv(path_or_buf=os.path.join(path,"Round_Time"))
        self.round_gas.to_csv(path_or_buf=os.path.join(path,"Round_Gas"))
        self.round_proof_times.to_csv(path_or_buf=os.path.join(path,"Round_Proof_Time"))
        self.round_training_local_time.to_csv(path_or_buf=os.path.join(path,"Round_Training_Local_Time"))
        self.round_score.to_csv(path_or_buf=os.path.join(path,"Round_Score"))
        self.round_classification_report.to_csv(path_or_buf=os.path.join(path,"Round_Classification_Report"))
        self.round_update_blockchain_time.to_csv(path_or_buf=os.path.join(path,"Round_Update_Blockchain_Time"))
        self.round_witness_time.to_csv(path_or_buf=os.path.join(path,"Round_Witness_Time"))
        self.round_proof_time.to_csv(path_or_buf=os.path.join(path,"Round_Proof_Time"))
        self.round_witness_size.to_csv(path_or_buf=os.path.join(path,"Round_Witness_Size"))
        self.round_proof_size.to_csv(path_or_buf=os.path.join(path,"Round_Proof_Size"))
        print(f"Values written for device : {self.deviceName}")
