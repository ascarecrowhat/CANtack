import pandas as pd
import numpy as np
from dataset_loader import load_dataset, ColumnHeader
from basic_attack import Attack
from enums.implementation_type import ImplementationType
from injection_function import inject_function
from masquerade_function import masquerade_function

class Progressive_injection_attackOLD(Attack):

    attack_parameters = dict()

    def __init__(self):
        super().__init__()

    """
        Return the original dataset with the addition of the specified number of packets with same payload

        Parameters
        ----------
        dataset: pandas.Dataframe
            The original dataset

        id: string
            The id of the injected packets as an hexadecimal string

        payloads: list[string]
            The payloads of the injected packets as hexadecimal strings, the number of injected packets is defined by the length of the list

        beginning_time_delta: int
            The time difference in seconds between the timestamp of the first message in the dataset (in seconds from 1st January 1970) and
            the beginning of the injection

        attack_type: enum
            ImplementationType.INJECTION for injection attack
            ImplementationType.MASQUERADE for masquerade attack

        **kwargs:
            injection_rate: integer
                The rate of injection of packets with refer to the average packet inter-arrival time of the id, not used for masquerade attacks
    """
    def __with_injection(self, dataset, id, payloads, beginning_time_delta, injection_rate, average_interval):
        return inject_function(dataset,
                                id = id,
                                payloads= payloads,
                                beginning_time_delta=beginning_time_delta,
                                injection_rate=injection_rate,
                                average_interval = average_interval
        )

    def __with_masquearade(self, dataset, id, payloads, beginning_time_delta):
        length = len(payloads[0])

        replacements = {
            (0, length): payloads
        }

        return masquerade_function(dataset, 
                                    id = id,
                                    beginning_time_delta = beginning_time_delta,
                                    replacements=replacements)


    def build_dataset(self, dataset, id, payloads, beginning_time_delta, attack_type, **kwargs):
        assert type(dataset) == pd.DataFrame
        assert type(id) == str
        assert type(payloads) == list
        for p in payloads:
            assert type(p) == str
            assert len(p) == len(payloads[0])
            try: 
                int(p, 2)
            except ValueError:
                raise ValueError('Payloads must be base 2 encoded')
        assert type(beginning_time_delta) == int
        assert beginning_time_delta >= 0
        assert type(attack_type) == ImplementationType

        dlc = dataset['Dlc'].tolist()[0]
        if len(payloads[0]) != dlc * 8:
            raise ValueError('Given payloads must fit the original payloads length (%d)' % dlc*8)

        if self.original_dataset is None:
            self.original_dataset = dataset

        if attack_type == ImplementationType.INJECTION:
            if 'injection_rate' not in kwargs or kwargs['injection_rate'] is None:
                raise ValueError('Injection rate needed for progressive injection attack')

            if 'average_interval' not in kwargs or kwargs['average_interval'] is None:
                    average_interval = None
            else:
                average_interval = kwargs['average_interval']
            self.vulnerable_dataset = self.__with_injection(dataset,
                                                            id = id,
                                                            payloads = payloads,
                                                            beginning_time_delta = beginning_time_delta, 
                                                            injection_rate = kwargs['injection_rate'],
                                                            average_interval = average_interval)
        else:
            self.vulnerable_dataset = self.__with_masquearade(dataset,
                                                            id = id,
                                                            payloads = payloads, 
                                                            beginning_time_delta = beginning_time_delta)

        return self.vulnerable_dataset

class Progressive_injection_attack(Attack):

    attack_parameters = dict()

    def __init__(self, _id, payloads, beginning_time_delta, attack_type, **kwargs):
        """
        Initialize the object with its parameters

        Parameters
        ---------
        id: string
            The id of the injected packets as an hexadecimal string

        payloads: list[string]
            The payloads of the injected packets as hexadecimal strings, the number of injected packets is defined by the length of the list

        beginning_time_delta: int
            The time difference in seconds between the timestamp of the first message in the dataset (in seconds from 1st January 1970) and
            the beginning of the injection

        attack_type: enum
            ImplementationType.INJECTION for injection attack
            ImplementationType.MASQUERADE for masquerade attack

        **kwargs:
            injection_rate: integer
                The rate of injection of packets with refer to the average packet inter-arrival time of the id, not used for masquerade attacks
        """
        super().__init__()
        assert type(_id) == str
        assert type(payloads) == list
        for p in payloads:
            assert type(p) == str
            assert len(p) == len(payloads[0])
            try: 
                int(p, 2)
            except ValueError:
                raise ValueError('Payloads must be base 2 encoded')
        assert type(beginning_time_delta) == int
        assert beginning_time_delta >= 0
        assert type(attack_type) == ImplementationType

        self.name = 'progressive%s' % id(self)
        self.attack_type = 'PROGRESSIVE'
        self.parameters = dict()
        self.parameters['id'] = _id
        self.parameters['payloads'] = payloads
        self.parameters['beginning_time_delta'] = beginning_time_delta
        self.parameters['implementation_type'] = attack_type.value

        dlc = dataset['Dlc'].tolist()[0]
        if len(payloads[0]) != dlc * 8:
            raise ValueError('Given payloads must fit the original payloads length (%d)' % dlc*8)

        if attack_type == ImplementationType.INJECTION:
            if 'injection_rate' not in kwargs or kwargs['injection_rate'] is None:
                raise ValueError('Injection rate needed for progressive injection attack')

            self.parameters['injection_rate'] = kwargs['injection_rate']

            if 'average_interval' not in kwargs or kwargs['average_interval'] is None:
                    self.parameters['average_interval'] = None
            else:
                self.parameters['average_interval'] = kwargs['average_interval']

    def __with_injection(self, dataset, id, payloads, beginning_time_delta, injection_rate, average_interval):
        return inject_function(dataset,
                                id = id,
                                payloads= payloads,
                                beginning_time_delta=beginning_time_delta,
                                injection_rate=injection_rate,
                                average_interval = average_interval
        )

    def __with_masquearade(self, dataset, id, payloads, beginning_time_delta):
        length = len(payloads[0])

        replacements = {
            (0, length): payloads
        }

        return masquerade_function(dataset, 
                                    id = id,
                                    beginning_time_delta = beginning_time_delta,
                                    replacements=replacements)


    def build_dataset(self, dataset):
        assert type(dataset) == pd.DataFrame
    
        if self.original_dataset is None:
            self.original_dataset = dataset

        if self.parameters['implementation_type'] == ImplementationType.INJECTION:
            self.vulnerable_dataset = self.__with_injection(dataset,
                                                            id = self.parameters['id'],
                                                            payloads = self.parameters['payloads'],
                                                            beginning_time_delta = self.parameters['beginning_time_delta'], 
                                                            injection_rate = self.parameters['injection_rate'],
                                                            average_interval = self.parameters['average_interval'])
        else:
            self.vulnerable_dataset = self.__with_masquearade(dataset,
                                                            id = self.parameters['id'],
                                                            payloads = self.parameters['payloads'], 
                                                            beginning_time_delta = self.parameters['beginning_time_delta'])

        return self.vulnerable_dataset
    
    def toJSON(self):
        dict_representation = dict()
        dict_representation['name'] = self.name
        dict_representation['attack_type'] = self.attack_type
        dict_representation['parameters'] = self.parameters
        return dict_representation

    def __str__(self):
        pass


if __name__ == "__main__":
    dataset = load_dataset()
    bia = Progressive_injection_attack(_id ='0F0', 
                                        payloads=['1' * 64]*4,
                                        beginning_time_delta = 1000, 
                                        attack_type=ImplementationType.INJECTION, 
                                        injection_rate=45)
    r =bia.build_dataset(dataset)
    #bia.visualize_changes()

    from pprint import pprint 
    pprint(bia.toJSON())