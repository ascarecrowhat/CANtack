from dataset_loader import load_dataset
from basic_attack import Attack
from basic_injection_attack import Basic_injection_attack
from drop_attack import Drop_attack
from fuzzy_injection import Fuzzy_injection_attack
from replay_attack import Replay_attack, Replacement, ReplacementType
from progressive_injection_attack import Progressive_injection_attack
from injection_function import calculate_average_interval
from enum import Enum
from enums.implementation_type import ImplementationType
from enums.attack_type import AttackType
from read import read, SIGN_TYPE
from tqdm import tqdm
from datetime import datetime

import pandas as pd
import numpy as np
import random, math, json
import warnings
import math


class FunctionType(Enum):
    Fuzzy = 1
    Replay = 2
    Drop = 3


class CleanSectionEndError(Exception):
    def __init__(self, value, _id):
        self.value = value + ' for id: ' + _id
        self.signal_id = _id


class AttackConfGenerator(object):
    dataset = None
    blacklisted_ids = None

    starting_time_delta = None
    first_packet_timestamp = None
    last_packet_timestamp = None
    max_delta = None

    attacks = None
    ids = None
    dataset_duration = None

    average_delta = 0
    cumulative_tampered_n = 0
    
    id_to_tampered_n = None
    id_to_signals = None
    id_to_period = None
    id_to_n_attacks = None

    # TODO: add also the remaing two types
    # TODO: make parameters customizable
    replacements_type_objs = {
        'FUZZY': Replacement(ReplacementType.FUZZY),
        'MIN': Replacement(ReplacementType.MIN),
        'MAX': Replacement(ReplacementType.MAX),
        'COUNTER': Replacement(ReplacementType.COUNTER),
        'REPLAY': ""
    }

    def __init__(self, dataset, blacklisted_ids=None, seed=42, starting_time=100):
        assert type(dataset) == pd.DataFrame
        assert type(seed) == int
        assert type(starting_time) == int
        assert starting_time > 0
        self.dataset = dataset
        self.ids = list(set(dataset['Id'].tolist()))
        if blacklisted_ids is not None:
            self.blacklisted_ids = blacklisted_ids
            for _id in self.blacklisted_ids:
                if _id in self.ids:
                    self.ids.remove(_id)
        self.attacks = list()
        self.starting_time_delta = starting_time
        self.first_packet_timestamp = dataset.head(1)['Time'].tolist()[0]
        self.last_packet_timestamp = dataset.tail(1)['Time'].tolist()[0]
        self.max_delta = self.last_packet_timestamp - self.first_packet_timestamp
        self.id_to_signals = dict()
        self.id_to_tampered_n = dict()
        self.id_to_n_attacks = dict()

        self.__compute_periods()
        self.__compute_global_period()

        random.seed(seed)

    def __compute_periods(self):
        assert type(self.dataset) == pd.DataFrame
        self.id_to_period = dict()
        for _id in self.ids:
            id_dataset = self.dataset[self.dataset['Id'] == _id]
            times = id_dataset['Time'].tolist()
            deltas = list()
            for i in range(1, len(id_dataset)):
                deltas.append(times[i] - times[i-1])
            self.id_to_period[_id] = max(deltas)
            

    def __compute_global_period(self):
        deltas = list()
        times = self.dataset['Time'].tolist()
        for i in range(1, len(self.dataset)):
            deltas.append(times[i] - times[i - 1])
        self.average_delta = max(deltas)
        # self.average_delta = np.mean(deltas)
        #self.average_delta += self.average_delta * 0.2
        #print(self.average_delta)

    def generate_fuzzy(self, ids, n_attacks, implementation_allowed, time_in_seconds=None, n_packet_range=None, allow_smart_fuzzying=False, just_smart_fuzzying=False, distance_between_attack=None, packets_between_attacks=None, allow_attacks_overlapping=False, id_to_signals=None):
        self.generate_function(function_type=FunctionType.Fuzzy,
                                ids=ids,
                                n_attacks=n_attacks,
                                implementation_allowed=implementation_allowed,
                                time_in_seconds=time_in_seconds,
                                n_packet_range=n_packet_range,
                                distance_between_attack=distance_between_attack,
                                packets_between_attacks=packets_between_attacks,
                                allow_smart_fuzzying=allow_smart_fuzzying,
                                just_smart_fuzzying=just_smart_fuzzying,
                                allow_attacks_overlapping=allow_attacks_overlapping,
                                id_to_signals=id_to_signals)

    def generate_drop(self, ids, n_attacks, time_in_seconds=None, n_packet_range=None, distance_between_attack=None, packets_between_attacks=None, allow_attacks_overlapping=False):
        self.generate_function(function_type=FunctionType.Drop,
                                ids=ids,
                                n_attacks=n_attacks,
                                implementation_allowed=[],
                                time_in_seconds=time_in_seconds,
                                n_packet_range=n_packet_range,
                                distance_between_attack=distance_between_attack,
                                packets_between_attacks=packets_between_attacks,
                                allow_attacks_overlapping=allow_attacks_overlapping)

    def generate_replay(self, ids, n_attacks, implementation_allowed, time_in_seconds=None, n_packet_range=None, conf=None, sniffing_from_the_beginning=True, distance_between_attack=None, packets_between_attacks=None, pattern_packets=None, allow_attacks_overlapping=False, not_full_replay=False, continuous_change_attack=False, adapt_sniffing_time=False, id_to_signals=None):
        self.generate_function(function_type=FunctionType.Replay,
                                ids=ids,
                                n_attacks=n_attacks,
                                implementation_allowed=implementation_allowed,
                                time_in_seconds=time_in_seconds,
                                n_packet_range=n_packet_range,
                                distance_between_attack=distance_between_attack,
                                packets_between_attacks=packets_between_attacks,
                                conf=conf,
                                sniffing_from_the_beginning=sniffing_from_the_beginning,
                                pattern_packets=pattern_packets,
                                allow_attacks_overlapping=allow_attacks_overlapping,
                                not_full_replay=not_full_replay,
                                continuous_change_attack=continuous_change_attack,
                                adapt_sniffing_time= adapt_sniffing_time,
                                id_to_signals=id_to_signals)

    def generate_function(self, function_type, ids, n_attacks, implementation_allowed, allow_attacks_overlapping, time_in_seconds=None, n_packet_range=None, distance_between_attack=None, packets_between_attacks=None, **kwargs):
        assert type(function_type) == FunctionType
        assert type(ids) == list
        for _id in ids:
            assert _id in self.ids
        assert type(n_attacks) == int
        assert n_attacks > 0
        if n_packet_range is not None:
            assert type(n_packet_range) == tuple or (type(n_packet_range) == list and len(n_packet_range) == 2)
            assert type(n_packet_range[0]) == int
            assert type(n_packet_range[1]) == int
            if time_in_seconds is not None:
                warnings.warn('Both n_attaccks and seconds parameters were specified. Seconds will be ignored')
        else:
            assert type(time_in_seconds) == int or type(time_in_seconds) == float
            assert ImplementationType.INJECTION not in implementation_allowed

        assert type(implementation_allowed) == list
        for t in implementation_allowed:
            assert type(t) == ImplementationType
        assert type(allow_attacks_overlapping) == bool
        assert distance_between_attack is not None or packets_between_attacks is not None
        if distance_between_attack is not None:
            assert type(distance_between_attack) == int
            assert distance_between_attack > 0
        if packets_between_attacks is not None:
            assert type(packets_between_attacks) == int
            assert packets_between_attacks > 0

        if function_type == FunctionType.Replay:
            conf = kwargs['conf']
            sniffing_from_the_beginning = kwargs['sniffing_from_the_beginning']
            pattern_packets = kwargs['pattern_packets']
            if conf is not None:
                assert type(conf) == dict
                assert SIGN_TYPE.COUNTER.value in conf.keys()
                assert SIGN_TYPE.CRC.value in conf.keys()
                assert SIGN_TYPE.PHYSVAL.value in conf.keys()

        elif function_type == FunctionType.Fuzzy:
            allow_smart_fuzzying = kwargs['allow_smart_fuzzying']
            just_smart_fuzzying = kwargs['just_smart_fuzzying']
            assert type(allow_smart_fuzzying) == bool
            assert type(just_smart_fuzzying) == bool
            

        # Instantiate attack objects
        for i in tqdm(range(n_attacks)):
            _id = random.choice(ids)
            if _id not in self.ids:
                warnings.warn('Id %s was blacklisted or it doesn\'t exists. Skipping')
                continue
            dataset_id = self.dataset[self.dataset['Id'] == _id]

            if _id not in self.id_to_signals:
                self.id_to_signals[_id] = read(dataset_id, verbose=False)[_id] if ('id_to_signals' not in kwargs or kwargs['id_to_signals'] is None) else kwargs['id_to_signals'][_id]
                self.id_to_tampered_n[_id] = 0
                self.id_to_n_attacks[_id] = 0

            signals = self.id_to_signals[_id]

             # pick a random number of packets to tamper if a range is specified
            if n_packet_range is not None:
                n_adding = random.randint(n_packet_range[0], n_packet_range[1])
            # otherwise get the number of packets to add base on the attack duration
            else:
                n_adding = int(time_in_seconds/self.id_to_period[_id])
                if n_adding == 0:
                    warn = 'Inserted time duration is shorter that average signal period (id: %s, period: %f). Skipping' % (_id, self.id_to_period[_id])
                    warnings.warn(warn)
                    ids.remove(_id)
                    continue

            # compute beginning time delta taking in consideration where other attacks ended for that specific id and
            #   the 'distance_between_attack' parameter
            btd = self.starting_time_delta
            if allow_attacks_overlapping:
                btd += math.ceil(self.id_to_tampered_n[_id] * self.id_to_period[_id])
                # if a distance between attaccks has been specified..
                if distance_between_attack is not None:
                    btd += (self.id_to_n_attacks[_id]) * distance_between_attack
                else:
                    btd += (self.id_to_n_attacks[_id]) * self.id_to_period[_id] * packets_between_attacks
                estimated_attack_duration = math.ceil(n_adding * self.id_to_period[_id])
            else:
                btd += math.ceil(self.cumulative_tampered_n * self.average_delta)
                # if a distance between attaccks has been specified..
                if distance_between_attack is not None:
                    btd += (i) * distance_between_attack
                else:
                    btd += (i) * self.average_delta * packets_between_attacks
                estimated_attack_duration = math.ceil(n_adding * self.average_delta)

            estimated_attack_end = btd + estimated_attack_duration

            # Return in case of finished dataset
            if estimated_attack_end > self.max_delta:
                ids.remove(_id)
                warn = 'Trace ended for id: %s(period: %ss), continuing with the others' % (_id, self.id_to_period[_id])
                warnings.warn(warn)

                if len(ids) != 0:
                    continue
                else:
                    print('All traces ended. Generated conf for just %d attaccks' % len(self.attacks))
                    return

            ############################ REPLAY
            if function_type == FunctionType.Replay:
                if kwargs['continuous_change_attack']:
                    long_signals = [sign for sign in signals if sign[2] == SIGN_TYPE.PHYSVAL and (sign[1] - sign[0] >= 4)]
                    if len(long_signals) == 0:
                        warn = 'The id %s has not a signal long atleast 4 bits to perform a continuous change attack' % (_id)
                        warnings.warn(warn)
                        ids.remove(_id)
                        continue
                    else:
                        replacements = dict()
                        attack_signal = random.choice(long_signals)
                        interval_len = attack_signal[1] - attack_signal[0]
                        max_value = int(math.pow(2, interval_len)) - 1
                        value = bin(np.random.randint(max_value))[2:].zfill(interval_len)
                        payload = value
                        interval = (attack_signal[0], attack_signal[1])
                        replacements[interval] = Replacement(ReplacementType.CONTINUOUS_CHANGE, payloads=payload)
                        
                elif conf is not None:
                    replacements = dict()
                    choices = dict()
                    # Choose before the attack for the signals to be able to avoid full replay if specified
                    for sign in signals:
                        sign_type = sign[2]
                        choices[(sign[0], sign[1])] = random.choice(conf[sign_type.value])
                    if kwargs['not_full_replay']:
                        phisvals = [(s[0], s[1]) for s in signals if s[2] == SIGN_TYPE.PHYSVAL]
                        if len(phisvals) > 0 and all([choices[p] == 'REPLAY' for p in phisvals]):
                            new_choice = random.choice(['MIN', 'MAX', 'PAYLOADS'])
                            to_change = random.choice(phisvals)
                            choices[to_change] = new_choice

                    for sign in signals:
                        interval = (sign[0], sign[1])
                        sign_type = sign[2]
                        # selecte Type of Replacement ramdomly from the configuration
                        tor = choices[(sign[0], sign[1])]
                        if tor == 'REPLAY':
                            # Don't add a replacement, it will be handled directly from the attack
                            pass
                        elif tor == 'PAYLOADS':
                            # also assign payloads attribute and set them to the half of representable value
                            interval_len = interval[1] - interval[0]
                            max_value = int(math.pow(2, interval_len)) - 1
                            value = bin(np.random.randint(max_value))[2:].zfill(interval_len)
                            payloads = [value] * n_adding
                            replacements[interval] = Replacement(ReplacementType.PAYLOADS, payloads=payloads)
                        elif tor == 'CONTINUOUS_CHANGE':
                            interval_len = interval[1] - interval[0]
                            max_value = int(math.pow(2, interval_len)) - 1
                            value = bin(np.random.randint(max_value))[2:].zfill(interval_len)
                            payload = value
                            replacements[interval] = Replacement(ReplacementType.CONTINUOUS_CHANGE, payloads=payload)
                        else:
                            replacements[interval] = self.replacements_type_objs[tor]
                else:
                    replacements = None 

                sniffing_time_delta =  0 if sniffing_from_the_beginning else random.randint(0, btd - 1)
                if kwargs['adapt_sniffing_time']:
                    sniffing_time_delta += self.id_to_tampered_n[_id]*(self.starting_time_delta-sniffing_time_delta)/n_attacks

                parameters = {
                    '_id': _id,
                    'beginning_time_delta': btd,
                    'sniffing_time_delta':sniffing_time_delta,
                    'injected_packets': n_adding,
                    'attack_type': random.choice(implementation_allowed),
                }
                
                if replacements is not None:
                    parameters['replacements'] = replacements

                if parameters['attack_type'] == ImplementationType.INJECTION:
                    parameters['injection_rate'] = 20
                else:
                    parameters['pattern_packets'] = pattern_packets

                a = Replay_attack(**parameters)
            
            ############################ FUZZY
            elif function_type == FunctionType.Fuzzy:
                parameters = {
                '_id': _id,
                'beginning_time_delta': btd,
                'injected_packets': n_adding,
                'attack_type': random.choice(implementation_allowed),
                'smart_fuzzying': random.choice([True, False]) if allow_smart_fuzzying else False
                }
                if allow_smart_fuzzying and just_smart_fuzzying:
                    parameters['smart_fuzzying'] = True
                if parameters['attack_type'] == ImplementationType.INJECTION:
                    parameters['injection_rate'] = 20

                if parameters['smart_fuzzying']:
                    parameters['bit_ranges'] = list()
                    for sig in signals:
                        parameters['bit_ranges'].append((sig[0], sig[1]))
                a = Fuzzy_injection_attack(**parameters)

            elif function_type == FunctionType.Drop:
                parameters = {
                '_id': _id,
                'beginning_time_delta': btd,
                'dropped_packets': n_adding,
                }
                a = Drop_attack(**parameters)
            else:
                raise Exception('Function type not supported')

            self.cumulative_tampered_n += n_adding
            self.id_to_tampered_n[_id] += n_adding
            self.id_to_n_attacks[_id] += 1
            self.attacks.append(a.toJSON())

    def export(self, path=None):
        if path is not None:
            assert type(path) == str
        else:
            path = './attack_%d_%s.json' % (len(self.attacks), datetime.now())
        print('Exporting..')
        with open(path, 'w+') as js:
            json.dump({'attacks': self.attacks}, js, indent=4)
        print('..done')


if __name__ == '__main__':
    df = load_dataset()

    """acg = AttackConfGenerator(df)
    acg.generate_fuzzy(ids=['1F7', '1F4'],
                       n_attacks=5,                             # n of attacck of this kind to generate
                       n_packet_range=[5, 40],                  # range of possibile packets to tampere for each attacck
                       implementation_allowed=[ImplementationType.INJECTION, ImplementationType.MASQUERADE],
                       allow_smart_fuzzying=True,
                       distance_between_attack=5)               # number of seconds between each attack

    # for each kind of signals, you must specify what kind of replacement you
    conf = {
        'PHYSVAL': ['FUZZY', 'MIN', 'MAX'],
        'COUNTER': ['FUZZY', 'COUNTER'],
        'CRC': ['FUZZY', 'MAX']
    }
    acg.generate_replay(ids=['1F7'],
                        n_attacks=5,
                        n_packet_range=[4, 50],
                        implementation_allowed=[ImplementationType.INJECTION, ImplementationType.MASQUERADE],
                        conf=conf,
                        distance_between_attack=5)

    from pprint import pprint
    pprint(acg.attacks)
    """
 