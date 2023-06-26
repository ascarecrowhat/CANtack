from enum import Enum
from abc import ABC, abstractmethod
from dataset_loader import load_dataset
from read import read, SIGN_TYPE
from enums.implementation_type import ImplementationType
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import webbrowser
from utils import Logger

"""
    Basic abastract class for attacck
"""
class Attack(ABC):
    original_dataset = None
    _vulnerable_dataset = None
    applied_attack = 0

    attack_name = None
    parameters = None

    def __init__(self):
        super().__init__()

    @property
    def vulnerable_dataset(self):
        return self._vulnerable_dataset
    
    @vulnerable_dataset.getter
    def vulnerable_dataset(self):
        return self._vulnerable_dataset

    @vulnerable_dataset.setter
    def vulnerable_dataset(self, value):
        self._vulnerable_dataset = value
        self.applied_attack += 1

    @abstractmethod
    def build_dataset(self):
        pass

    def get_tampered_rows(self):
        return self.vulnerable_dataset[self.vulnerable_dataset['IsTampered'] == 1]

    def get_original_rows(self):
        return self.vulnerable_dataset[self.vulnerable_dataset['IsTampered'] == 0]
    
    def get_stats(self, verbose=False):
        stats = dict()

        tampered_rows = self.get_tampered_rows()
        stats['N_applied_attack'] = self.applied_attack
        stats['Tampered_ids'] = list(set(tampered_rows['Id'].tolist()))
        stats['N_of_tampered_ids'] = len(stats['Tampered_ids'])
        stats['N_tampered_rows'] = tampered_rows.shape[0]
        stats['N_added_rows'] = self.vulnerable_dataset.shape[0] - self.original_dataset.shape[0]
        
        if verbose:
            print("""
                %d attaccks were applied
                %d ids were tampered
                %d rows were tampered (out of %d)
                %d rows were added
            """ % (stats['N_applied_attack'],
                    stats['N_of_tampered_ids'],
                    stats['N_tampered_rows'], self.vulnerable_dataset.shape[0],
                    stats['N_added_rows']
                    )) 
        
        return stats

    def visualize_changes(self, export=True):
        stats = self.get_stats()
        tampered_ids = stats['Tampered_ids']

        print('Running read...')
        read_signals = read(self.vulnerable_dataset[self.vulnerable_dataset['Id'].isin(tampered_ids)])
        print('..done')


        for tampered_id in tampered_ids:
            signals = read_signals[tampered_id]
            print("Found %d signals for id %s" % (len(signals),tampered_id))
            figs = list()
            original_dataset_id = self.original_dataset[self.original_dataset['Id'] == tampered_id]
            tampered_dataset_id = self.vulnerable_dataset[self.vulnerable_dataset['Id'] == tampered_id]
            for sign in signals:
                if sign[2] in [SIGN_TYPE.BINARY, SIGN_TYPE.CRC]:
                    continue
                
                original_dataset_sign = original_dataset_id.copy(deep=True)
                original_dataset_sign['Payload'] = original_dataset_sign.apply(lambda x: int(x.Payload[sign[0]:sign[1]], 2), axis=1)
                original_dataset_sign['Type'] = ['Original_signal' for _ in range(original_dataset_sign.shape[0])]
                original_dataset_sign.drop(columns=['Can#','Dlc', 'Id', 'IsTampered'])
                
                tampered_dataset_sign = tampered_dataset_id.copy(deep=True)
                tampered_dataset_sign['Payload'] = tampered_dataset_sign.apply(lambda x: int(x.Payload[sign[0]:sign[1]], 2), axis=1)
                tampered_dataset_sign['Type'] = ['Tampered_signal' for _ in range(tampered_dataset_sign.shape[0])]
                tampered_dataset_sign.drop(columns=['Can#','Dlc', 'Id'])

                just_tampered_rows = tampered_dataset_sign[tampered_dataset_sign['IsTampered'] == 1].copy(deep=True)
                just_tampered_rows['Type'] = ['Tampered_packets' for _ in range(just_tampered_rows.shape[0])]
                just_tampered_rows.drop(columns=['IsTampered'])
                tampered_dataset_sign.drop(columns=['IsTampered'])
                
                df = pd.concat([original_dataset_sign, tampered_dataset_sign, just_tampered_rows])
                
                # Find optimal visualition range
                first_tampered_timestamp = just_tampered_rows['Time'].tolist()[0]
                last_tampered_timestamp = just_tampered_rows['Time'].tolist()[-1]
                delta_timestamp = last_tampered_timestamp - first_tampered_timestamp
                range_x = (first_tampered_timestamp - delta_timestamp, last_tampered_timestamp + delta_timestamp)

                fig = px.line(df, x='Time',
                                    y='Payload',
                                    color='Type',
                                    title='Signal (%d, %d) of type: %s appearances for id %s' % (sign[0], sign[1], sign[2], tampered_id),
                                    range_x= range_x
                                    )
                if export:
                    figs.append(fig)
                else:
                    fig.show()
            if export:
                filename = 'graphs_%s.html' %(tampered_id)
                with open(filename, 'w') as f:
                    for fig in figs:
                        f.write(fig.to_html(full_html=True, include_plotlyjs='cdn'))
                webbrowser.open(filename, new=1)

    def export_dataset(self, path='vulnerable_dataset.csv', verbose=True):
        self.get_stats(verbose=verbose)
        print('Exporting..')
        self.vulnerable_dataset.to_csv(path)
        print('..Done') 

if __name__ == "__main__":
    from fuzzy_injection import Fuzzy_injection_attack
    dataset = load_dataset()
    fIA = Fuzzy_injection_attack()
    time_delta = 1000
    id = '0F0'
    time = dataset['Time'][0] + time_delta
    fIA.build_dataset(dataset, id, 1000, 200, ImplementationType.MASQUERADE, False)
    fIA.visualize_changes(export=True)