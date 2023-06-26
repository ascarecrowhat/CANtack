import pandas as pd
import numpy as np
from dataset_loader import load_dataset, ColumnHeader
from basic_attack import Attack
from enums.implementation_type import ImplementationType
from injection_function import inject_function
from masquerade_function import masquerade_function

class Basic_injection_attack(Attack):

    def __init__(self, _id, payload, beginning_time_delta, injected_packets, attack_type, **kwargs):
        """
        Initialize the object

        Parameters
        ----------

        id: string
            The id of the injected packets as an hexadecimal string

        payload: string
            The payload of the injected packets as binary string

        beginning_time_delta: int
            The time difference in seconds between the timestamp of the first message in the dataset (in seconds from 1st January 1970) and
            the beginning of the injection

        injected_packets: integer
            The number of packets injected

        attack_type: enum
            ImplementationType.INJECTION for injection attack
            ImplementationType.MASQUERADE for masquerade attack

        **kwargs:
            injection_rate: integer
                The rate of injection of packets with refer to the average packet inter-arrival time of the id, not used for masquerade attacks
        """
        assert type(payload) == str
        assert type(beginning_time_delta) == int or type(beginning_time_delta) == float
        assert type(injected_packets) == int
        assert type(attack_type) == ImplementationType

        self.attack_name = 'basic%s' % id(self)
        self.attack_type = 'BASIC'
        self.parameters = dict()

        try:
            int(payload, 2)
        except ValueError:
            raise ValueError('Payload must be a string representing a number encoded in base 2')

        self.parameters['id'] = _id
        self.parameters['payload'] = payload
        self.parameters['beginning_time_delta'] = beginning_time_delta
        self.parameters['injected_packets'] = injected_packets
        self.parameters['implementation_type'] = attack_type.value

        if attack_type == ImplementationType.INJECTION:
            if 'injection_rate' not in kwargs or kwargs['injection_rate'] is None:
                raise ValueError('Injection rate needed for basic injection attack')

            if 'average_interval' not in kwargs or kwargs['average_interval'] is None:
                self.parameters['average_interval'] = None
            else:
                self.parameters['average_interval'] = kwargs['average_interval']
            
            self.parameters['injection_rate'] = kwargs['injection_rate']

    def __with_injection(self, dataset, id, payloads, beginning_time_delta, injected_packets, injection_rate, average_interval):
        return inject_function(dataset,
                                id=id,
                                payloads=payloads,
                                beginning_time_delta=beginning_time_delta,
                                injection_rate=injection_rate,
                                average_interval=average_interval
                                )

    def __with_masquearade(self, dataset, id, payloads, beginning_time_delta, injected_packets):
        
        length = len(payloads[0])
        
        replacements = {
            (0, length) : payloads
        }
       
        return masquerade_function (dataset,
                                    id=id,
                                    beginning_time_delta=beginning_time_delta,
                                    replacements=replacements
        )

    def build_dataset(self, dataset):
        """
        Build and return the dataset
        """
        assert type(dataset) == pd.DataFrame
    
        dlc = dataset['Dlc'].tolist()[0]
        if len(self.parameters['payload']) != dlc * 8:
            raise ValueError('The dataset payloads length must be the same of the substituting ones (%d)' % dlc*8)

        if self.original_dataset is None:
            self.original_dataset = dataset

        payloads = [self.parameters['payload']] * self.parameters['injected_packets']

        if self.parameters['implementation_type'] == ImplementationType.INJECTION:       
            self.vulnerable_dataset = self.__with_injection(dataset, 
                                                            id=self.parameters['id'],
                                                            payloads=payloads, 
                                                            beginning_time_delta=self.parameters['beginning_time_delta'], 
                                                            injected_packets=self.parameters['injected_packets'], 
                                                            injection_rate = self.parameters['injection_rate'],
                                                            average_interval = self.parameters['average_interval'])
        else:
            self.vulnerable_dataset = self.__with_masquearade(dataset=dataset, 
                                                                id = self.parameters['id'],
                                                                payloads=payloads, 
                                                                beginning_time_delta=self.parameters['beginning_time_delta'], 
                                                                injected_packets=self.parameters['injected_packets'])

        return self.vulnerable_dataset

    def toJSON(self):
        dict_representation = dict()

        dict_representation['name'] = self.attack_name
        dict_representation['attack_type'] = self.attack_type
        dict_representation['parameters'] = self.parameters
        dict_representation['parameters']['payload'] = hex(int(dict_representation['parameters']['payload'], 2)).upper()

        return dict_representation

    def __str__(self):
        return str(self.toJSON())


if __name__ == "__main__":
    dataset = load_dataset()
    bia = Basic_injection_attack(_id = '0F0', 
                                payload = '1' * 64, 
                                beginning_time_delta=1000, 
                                injected_packets=30, 
                                attack_type = ImplementationType.MASQUERADE, 
                                injection_rate=45)
    bia.build_dataset(dataset)
    #bia.visualize_changes()
    bia.get_stats(verbose=True)
    
    from pprint import pprint
    pprint(bia.toJSON())