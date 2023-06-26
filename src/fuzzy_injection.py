import pandas as pd
import numpy as np
import random
from dataset_loader import load_dataset, ColumnHeader
from basic_attack import Attack
from enums.implementation_type import ImplementationType
from injection_function import inject_function
from masquerade_function import masquerade_function
from read import read, SIGN_TYPE

class Fuzzy_injection_attack(Attack):

    def __init__(self, _id, beginning_time_delta, injected_packets, attack_type, smart_fuzzying=False, **kwargs):
        """
        Initializa attack
        id: string
            The id of the injected packets as an hexadecimal string

        beginning_time_delta: float
            The time difference in seconds between the timestamp of the first message in the dataset (in seconds from 1st January 1970) and
            the beginning of the injection      

        injected_packets: integer
            The number of packets injected

        attack_type: Enum
            ImplementationType.INJECTION for injection attack
            ImplementationType.MASQUERADE for masquerade attack

        smart_fuzzying: bool, optional (default value: False)
            If true, use the READ algorithm (https://ieeexplore.ieee.org/document/8466914) to find the signals inside the payloads and randomly change only those bits

        **kwargs:
            injection_rate: integer
                The rate of injection of packets with refer to the average packet inter-arrival time of the id. Not used for masquerade attacks.

            bit_ranges: list(couple(int, int))
                The edges of the original payload to substitute, ignored for smart_fuzzying

            seed: int
                Seed for the random generator
        """
        super().__init__()
        assert type(_id) == str
        assert type(beginning_time_delta) == int or type(beginning_time_delta) == float
        assert type(injected_packets) == int
        assert type(attack_type) == ImplementationType
        assert type(smart_fuzzying) == bool

        self.parameters = dict()
        self.name = 'fuzzy%s'% id(self)
        self.attack_type = 'FUZZY'

        if 'seed' in kwargs and kwargs['seed'] is not None:
            assert type(kwargs['seed']) == int
            random.seed(kwargs['seed'])
            self.parameters['seed'] = kwargs['seed']

        self.parameters['id'] = _id
        self.parameters['beginning_time_delta'] = beginning_time_delta
        self.parameters['injected_packets'] = injected_packets
        self.parameters['implementation_type'] = attack_type.value
        self.parameters['smart_fuzzying'] = smart_fuzzying
        if 'intervals' in kwargs:
            self.parameters['intervals'] = kwargs['intervals']

        if 'intervals' not in kwargs and 'bit_ranges' in kwargs and kwargs['bit_ranges'] is not None:
                assert type(kwargs['bit_ranges']) == list
                assert all(list(map(type, x)) == [int, int] for x in kwargs['bit_ranges']) 
                self.parameters['intervals'] = kwargs['bit_ranges']
        elif 'intervals' not in kwargs and not smart_fuzzying:
            self.parameters['intervals'] = [(0, packet_length)]

        if attack_type == ImplementationType.INJECTION:
            if 'injection_rate' not in kwargs or kwargs['injection_rate'] is None:
                raise ValueError('Injection rate needed for fuzzy injection attack')
            self.parameters['injection_rate'] = kwargs['injection_rate']

            if 'average_interval' not in kwargs or kwargs['average_interval'] is None:
                self.parameters['average_interval'] = None
            else:
                self.parameters['average_interval'] = kwargs['average_interval']
                
    def __with_injection(self, dataset, id, payloads, beginning_time_delta, injected_packets, injection_rate, average_interval):
        return inject_function(dataset,
                                id,
                                payloads,
                                beginning_time_delta,
                                injection_rate,
                                average_interval=average_interval)

    def __with_masquearade(self, dataset, id, beginning_time_delta, replacements):
        return masquerade_function(dataset,
                                    id,
                                    beginning_time_delta,
                                    replacements)

    def build_dataset(self, dataset):
        """
        Return the original dataset with the addition of the specified number of packets with same payload

        Parameters
        ----------
        dataset: pandas.Dataframe
            The original dataset
        """
        assert type(dataset) == pd.DataFrame

        self.original_dataset = dataset
        id_dataset = dataset[dataset['Id'] == self.parameters['id']]
        indices = id_dataset.index
        packet_length = id_dataset['Dlc'][indices[0]] * 8

        if 'intervals' not in self.parameters and self.parameters['smart_fuzzying']:
            signals = read(id_dataset, verbose=False)[self.parameters['id']]
            self.parameters['intervals'] = list()
            for sig in signals:
                self.parameters['intervals'].append((sig[0], sig[1]))

        replacements = {}

        for i in range(self.parameters['injected_packets']):
            for interval in self.parameters['intervals']:
                if not interval in replacements:
                    replacements[interval] = []
                fuzzy_bits = interval[1] - interval[0]
                rand_num = random.getrandbits(fuzzy_bits)
                rand_bits = bin(rand_num)[2:].zfill(fuzzy_bits)
                replacements[interval].append(rand_bits)
        
        if len(replacements.keys()) == 0:
            return dataset

        if self.parameters['implementation_type'] == ImplementationType.INJECTION:
            # Get the first payload, will be replaced for all bits except immutable ones (needed only because they may be either all 0s or all 1s)
            base_payload = id_dataset['Payload'][indices[0]]
            n_of_packets = len(list(replacements.values())[0]) 
            payloads = []

            # As injection_func takes full payloads as input, reconstruct them
            for i in range(n_of_packets):
                payload = base_payload
                for interval in replacements.keys():
                    payload = replacements[interval][i].join([payload[:interval[0]], payload[interval[1]:]])
                payloads.append(payload)

            self.vulnerable_dataset = self.__with_injection(dataset,
                                                            self.parameters['id'],
                                                            payloads,
                                                            self.parameters['beginning_time_delta'],
                                                            self.parameters['injected_packets'],
                                                            self.parameters['injection_rate'],
                                                            self.parameters['average_interval'])
        else:
            self.vulnerable_dataset = self.__with_masquearade(dataset,
                                                                self.parameters['id'],
                                                                self.parameters['beginning_time_delta'],
                                                                replacements)

        return self.vulnerable_dataset

    def toJSON(self):
        dict_representation = dict()
        dict_representation['name'] = self.name
        dict_representation['attack_type'] = self.attack_type
        dict_representation['parameters'] = self.parameters
        return dict_representation


    def __string__(self):
        return str(self.toJSON())

if __name__ == "__main__":
    df2 = load_dataset()

    time_delta = 1000
    _id = '0F0'
    time = 0
    injection_rate = 20

    random.seed(123)
    fuz2 = Fuzzy_injection_attack( _id, time_delta, 5, ImplementationType.MASQUERADE, False)
    df2 = fuz2.build_dataset(df2)
    
    from pprint import pprint
    pprint(fuz2.toJSON())