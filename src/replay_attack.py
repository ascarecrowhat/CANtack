import pandas as pd
import numpy as np
from dataset_loader import load_dataset, ColumnHeader
from basic_attack import Attack
from enums.implementation_type import ImplementationType
from injection_function import inject_function
from masquerade_function import masquerade_function
from enum import Enum
import random
import math

class ReplacementType(str, Enum):
    PAYLOADS = "PAYLOADS"
    FUZZY = "FUZZY"
    MIN = "MIN"
    MAX = "MAX"
    CONTINUOUS_CHANGE = "CONTINUOUS_CHANGE"
    COUNTER = "COUNTER"

class Replacement:
    """
        This class specifies what will be the replacement for a certain range of bits of the payloads.

        Parameters
        ----------
        replacement_type: Enum
            Defines the type of the replacements, based on the type different parameters will be requested. It can be:

            ReplacementType.PAYLOADS to substitute a list of chosen payloads
                Additional Parameters:
                    payloads: list(string)
                        List of the binary strings that will be replaced into the chosen range. The length of the strings needs to match the length of the ranges. The length of the list
                        needs to match the number of injected packets

            ReplacementType.FUZZY to substitute random bits inside the specified range
                Additional Parameters:
                    seed: int, optional
                        The seed of the random generator, not seeded if not specified

            ReplacementType.MIN to replace all the bits in the range with their minimum value detected in the dataset

            ReplacementType.MAX to replace all the bits in the range with their maximum value detected in the dataset

            ReplacementType.CONTINUOUS_CHANGE to choose the final payload that will have the signal in the specified bit range. The payloads of the tampered packets will start from the
            last sniffed value before the attack and increase/decrease continuosly until the specified value is reached
                Additional Parameters:
                    payloads: string
                        The final value of the payload of the tampered messages

            ReplacementType.COUNTER to threat the chosen range as a counter, that will increase/decrease by one at every tampered message, starting from the last value read from the
            last sniffed value before the attack
                Additional Parameters:
                    is_counter_decreasing: bool, optional
                        Specifies if the counter increases or decreases its value at every step. Default False
                        

    """
    replacement_type = None
    payloads = None
    seed = None
    is_counter_decreasing = None

    def __init__(self, replacement_type, payloads=None, seed=None, is_counter_decreasing=False):
        assert type(replacement_type) == ReplacementType

        self.replacement_type = replacement_type
        self.seed = seed

        if replacement_type == ReplacementType.PAYLOADS:
            assert type(payloads) == list
            self.payloads = payloads
        elif replacement_type == ReplacementType.FUZZY:
            if seed is not None:
                self.seed = seed
        elif replacement_type == ReplacementType.MIN:
            pass
        elif replacement_type == ReplacementType.MAX:
            pass
        elif replacement_type == ReplacementType.CONTINUOUS_CHANGE:
            assert type(payloads) == str
            try:
                int(payloads, 2)
            except:
                raise ValueError('Payload must be base 2 coded')
            self.payloads = payloads
        elif replacement_type == ReplacementType.COUNTER:
            self.is_counter_decreasing = is_counter_decreasing
        else:
            raise ValueError('This is not an element of the enum')
    
    def toJSON(self):
        dict_representation = dict()
        if self.seed:
            dict_representation['seed'] = self.seed
        if self.is_counter_decreasing:
            dict_representation['is_counter_decreasing'] = self.is_counter_decreasing
        if self.payloads:
            dict_representation['payloads'] = self.payloads
        return dict_representation

    
    def __str__(self):
        return str(self.toJSON())


class Replay_attack(Attack):

    attack_parameters = dict()

    def __init__(self, _id, beginning_time_delta, sniffing_time_delta, injected_packets, attack_type, pattern_packets=None, is_random_start=False, **kwargs):
        """
        Initialize the object

        Parameters

        id: string
            The id of the injected packets as an hexadecimal string

        beginning_time_delta: float
            The time difference in seconds between the timestamp of the first message in the dataset (in seconds from 1st January 1970) and
            the beginning of the injection
        
        sniffing_time_delta: float
            The time difference in seconds between the timestamp of the first message in the dataset (in seconds from 1st January 1970) and
            the beginning of sniffing packets in order to replay them later

        injected_packets: integer
            Total number of packets injected.

        attack_type: Enum
            ImplementationType.INJECTION for injection attack
            ImplementationType.MASQUERADE for masquerade attack

        pattern_packets: integer, optional
            Number of actual different packets that are used for the attack. If specified the same pattern of packets will be used until injected_packets number is reached. If
            not specified there is no pattern and all the packets are different. 
            
        is_random_start: boolean, optional
            Boolean that indicates if the attack starts from the first packet sniffed or a random starting point among the sniffed packets s selected. Initialized to False.   
            
        **kwargs:
            injection_rate: integer
                The rate of injection of packets with refer to the average packet inter-arrival time of the id. If not specified the injection rate will be 1. Not used for masquerade attacks.
            
            replacements: dict(couple(int, int) -> Replacement]
                A dict containing the couple representing bit intervals as key and a Replacement object for the specified bitrange. Look for Replacement definition for more information.
        """
        super().__init__()
        assert type(beginning_time_delta) == int or type(beginning_time_delta) == float
        assert beginning_time_delta >= 0
        assert type(sniffing_time_delta) == int or type(sniffing_time_delta) == float
        assert sniffing_time_delta >= 0
        assert type(injected_packets) == int
        assert type(attack_type) == ImplementationType
        assert type(is_random_start) == bool

        self.attack_type  = 'REPLAY'
        self.attack_name = 'replay%s' % id(self)

        self.parameters = dict()
        self.parameters['id'] = _id
        self.parameters['beginning_time_delta'] = beginning_time_delta
        self.parameters['sniffing_time_delta'] = sniffing_time_delta
        self.parameters['injected_packets'] = injected_packets
        self.parameters['implementation_type'] = attack_type.value
        self.parameters['is_random_start'] = is_random_start
        self.parameters['replacements'] = kwargs['replacements'] if 'replacements' in kwargs else {}

        if pattern_packets is not None:
            assert type(pattern_packets) == int
            self.parameters['pattern_packets'] = pattern_packets
        else:
            self.parameters['pattern_packets'] = injected_packets

        if injected_packets <= 0:
            raise ValueError('At least needs to be one packet injected')

        if self.parameters['pattern_packets'] <= 0:
            raise ValueError('At least needs to be one packet in the pattern')

        if sniffing_time_delta > beginning_time_delta:
            raise ValueError('Sniffing time delta must be lower than the beggining time delta (%d)' % beginning_time_delta)

        if attack_type == ImplementationType.INJECTION:
            if 'injection_rate' not in kwargs or kwargs['injection_rate'] is None:
                raise ValueError('Injection rate needed for fuzzy injection attack')
            self.parameters['injection_rate'] = kwargs['injection_rate']
            
            if 'average_interval' not in kwargs or kwargs['average_interval'] is None:
                self.parameters['average_interval'] = None
            else:
                self.parameters['average_interval'] = kwargs['average_interval']

    def __with_injection(self, dataset, id, payloads, beginning_time_delta, injection_rate, average_interval):
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
        Return the original dataset with the addition of the specified number of packets sniffed from the previous traffic at the specified time point, either unchanged of with
        some specified replacement.

        Parameters
        ----------
        dataset: pandas.Dataframe
            The original dataset
        """
        assert type(dataset) == pd.DataFrame
        if self.original_dataset is None:
            self.original_dataset = dataset
        
        # Take the payloads from the dataset taking injected_packets packets from the id starting from sniffing_time_delta and before starting the attack
        init_time = dataset['Time'].iloc[0]
        initial_sniffing = init_time + self.parameters['sniffing_time_delta']
        final_sniffing = init_time + self.parameters['beginning_time_delta']
        dataset_id = dataset.loc[(dataset['Id'] == self.parameters['id']) & (dataset['IsTampered'] == 0)]
        dataset_sniffed_id = dataset_id.loc[(dataset['Time'] > initial_sniffing) & (dataset['Time'] < final_sniffing)]
        
        payload_sniffed = dataset_sniffed_id['Payload'].tolist()

        if len(payload_sniffed) < self.parameters['pattern_packets']:
            raise ValueError('Not enough sniffing time (%ds) for the current pattern (you sniffed %d payloads) --> Id: %s'
                             % (self.parameters['beginning_time_delta'] - self.parameters['sniffing_time_delta'],
                                len(payload_sniffed),
                                self.parameters['id']))
        
        packet_length = dataset_sniffed_id['Dlc'].tolist()[0] * 8

        if self.parameters['is_random_start']:
            #Choose randomly the pattern
            index_payload_sniffed = np.array([x for x in range(len(payload_sniffed) - (self.parameters['pattern_packets'] - 1) - 1)])
            first_packet_pattern = np.random.choice(index_payload_sniffed)
            pattern_payload = payload_sniffed[first_packet_pattern:(first_packet_pattern + self.parameters['pattern_packets'])]
        else:
            pattern_payload = payload_sniffed[:self.parameters['pattern_packets']]

        payloads = pattern_payload * int(np.floor(self.parameters['injected_packets'] / self.parameters['pattern_packets']))
        payloads = payloads.__add__(pattern_payload[:(self.parameters['injected_packets'] % self.parameters['pattern_packets'])])

        assert len(payloads) == self.parameters['injected_packets']

        # Handle the replacement of the specified signals, if any
        if bool(self.parameters['replacements']) and self.parameters['replacements'] is not None:
            replacements = self.parameters['replacements']

            assert type(replacements) == dict
            assert all((type(x) == tuple and list(map(type, x)) == [int, int] and x[0] >= 0 and x[1] <= packet_length and x[0] < x[1]) for x in replacements.keys())
            assert all((type(x) == Replacement) for x in replacements.values())

            for interval in replacements.keys():
                rep = replacements[interval]
                replacement_type = rep.replacement_type
                new_payloads = []
                
                if replacement_type == ReplacementType.PAYLOADS:
                    assert len(rep.payloads) == self.parameters['injected_packets']
                    new_payloads = rep.payloads
                
                elif replacement_type == ReplacementType.FUZZY:
                    if rep.seed is not None:
                        random.seed(rep.seed)
                    fuzzy_bits = interval[1] - interval[0]
                    new_payloads = [(bin(random.getrandbits(fuzzy_bits))[2:].zfill(fuzzy_bits)) for i in range(len(payloads))]
                
                elif replacement_type == ReplacementType.MIN:
                    payloads_id = dataset_id['Payload'].tolist()
                    min_value = min(x[interval[0]:interval[1]] for x in payloads_id)
                    new_payloads = [min_value for i in range(len(payloads))]
                
                elif replacement_type == ReplacementType.MAX:
                    payloads_id = dataset_id['Payload'].tolist()
                    max_value = max(x[interval[0]:interval[1]] for x in payloads_id)
                    new_payloads = [max_value for i in range(len(payloads))]
                
                elif replacement_type == ReplacementType.CONTINUOUS_CHANGE:
                    last_payload = payload_sniffed[-1]
                    initial_signal_value = last_payload[interval[0]:interval[1]]
                    final_signal_value = rep.payloads
                    bits_num = len(initial_signal_value)
                    assert len(final_signal_value) == bits_num
                    average_change = (int(final_signal_value, 2) - int(initial_signal_value, 2)) / self.parameters['injected_packets']
                    new_payloads = [bin(round(int(initial_signal_value, 2) + average_change * (i + 1)))[2:].zfill(bits_num) for i in range(len(payloads))]
                
                elif replacement_type == ReplacementType.COUNTER:
                    last_payload = payload_sniffed[-1]
                    last_counter_value = last_payload[interval[0]:interval[1]]
                    bits_num = len(last_counter_value)
                    bits_values = int(math.pow(2, bits_num))
                    if rep.is_counter_decreasing:
                        new_payloads = [bin((int(last_counter_value, 2) - (i + 1)) % bits_values)[2:].zfill(bits_num) for i in range(len(payloads))]
                    else:
                        new_payloads = [bin((int(last_counter_value, 2) + i + 1) % bits_values)[2:].zfill(bits_num) for i in range(len(payloads))]
                else:
                    raise ValueError('This is not an element of the enum')

                for i in range(len(new_payloads)):
                    new_payload = new_payloads[i]
                    assert len(new_payload) == interval[1] - interval[0]
                    payloads[i] = new_payload.join([payloads[i][:interval[0]], payloads[i][interval[1]:]])


        if self.parameters['implementation_type'] == ImplementationType.INJECTION:
            self.vulnerable_dataset = self.__with_injection(dataset,
                                                            self.parameters['id'],
                                                            payloads,
                                                            self.parameters['beginning_time_delta'],
                                                            self.parameters['injection_rate'],
                                                            self.parameters['average_interval'])
        else:
            replacements={}
            replacements[(0, packet_length)] = payloads

            self.vulnerable_dataset = self.__with_masquearade(dataset,
                                                                self.parameters['id'],
                                                                self.parameters['beginning_time_delta'],
                                                                replacements)

        return self.vulnerable_dataset

    def toJSON(self):
        dict_representation = dict()

        dict_representation['name'] = self.attack_name
        dict_representation['attack_type'] = self.attack_type
        dict_representation['parameters'] = self.parameters
        
        replacements = dict_representation['parameters']['replacements']
        dict_representation['parameters'].pop('replacements', None)
        
        replacements_list = list()
        for key in replacements.keys():
            replacement = dict()
            replacement['start'] = key[0]
            replacement['end'] = key[1]
            replacement['replacement_type'] = replacements[key].replacement_type.value
            replacement['parameters'] = replacements[key].toJSON()
            replacements_list.append(replacement)
        dict_representation['parameters']['replacements'] = replacements_list

        return dict_representation

    def __str__(self):
        return str(self.toJSON())


if __name__ == "__main__":
    dataset = load_dataset()
    payloads = ['0000']*5 + ['0110']*5
    payloads_replacement = Replacement(ReplacementType.PAYLOADS, payloads=payloads)
    fuzzy_replacement = Replacement(ReplacementType.FUZZY, seed=42)
    counter_replacement = Replacement(ReplacementType.COUNTER)
    decr_counter_replacement = Replacement(ReplacementType.COUNTER, is_counter_decreasing=True)
    min_replacement = Replacement(ReplacementType.MIN)
    max_replacement = Replacement(ReplacementType.MAX)
    continuous_replacement = Replacement(ReplacementType.CONTINUOUS_CHANGE, payloads='00000000')
    replacements = {
                    (0, 4): payloads_replacement,
                    (13, 20): fuzzy_replacement,
                    (52, 56): counter_replacement,
                    (25, 30): decr_counter_replacement,
                    (56, 64): continuous_replacement
                    }
    random.seed(23)
    rep = Replay_attack(_id='0F0', 
                        beginning_time_delta=600.0, 
                        sniffing_time_delta=100.0, 
                        injected_packets=10, 
                        attack_type=ImplementationType.MASQUERADE, 
                        pattern_packets=5, 
                        replacements=replacements)
    res = rep.build_dataset(dataset)
                            
    tamp_payloads = res.loc[res['IsTampered'] == 1]['Payload'].tolist()

    print('Nuovi payload')
    for payload in tamp_payloads:
        print(payload)

    #rep.visualize_changes()

    from pprint import pprint

    pprint(rep.toJSON())