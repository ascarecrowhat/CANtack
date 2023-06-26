from dataset_loader import load_dataset
from basic_attack import Attack
from basic_injection_attack import Basic_injection_attack
from dos_attack import Dos_attack
from drop_attack import Drop_attack
from fuzzy_injection import Fuzzy_injection_attack
from replay_attack import Replay_attack, Replacement, ReplacementType
from progressive_injection_attack import Progressive_injection_attack
from injection_function import calculate_average_interval
from enums.implementation_type import ImplementationType
from enums.attack_type import AttackType
from argparse import ArgumentParser
from pathlib import Path
from enum import Enum
from dataset_loader import DEIBVehicle
from tqdm import tqdm
import json, os, errno
import pandas as pd

class EnsambleAttack(Attack):
    def __init__(self):
        super().__init__()

    def build_dataset(self, dataset, attacks):
        assert type(dataset) == pd.DataFrame
        assert type(attacks) == list

        if self.original_dataset is None:
            self.original_dataset = dataset

        id_average_interval = dict()

        for attack in attacks:
            if 'parameters' in attack and 'id' in attack['parameters'] and 'implementation_type' in attack['parameters'] and attack['parameters']['implementation_type'] == ImplementationType.INJECTION:
                if not 'injection_rate' in attack['parameters']:
                    raise ValueError('Injection rate is needed for INJECTION implementation type')
                id = attack['parameters']['id']
                if id not in id_average_interval:
                    avg = calculate_average_interval(dataset, id)
                    if avg is not None:
                        id_average_interval[id] = avg

        print('Attacks in progress...')

        for i in tqdm(range(len(attacks))):
            attack = attacks[i]
            dataset = self.vulnerable_dataset if self.vulnerable_dataset is not None else dataset
            attack_type = AttackType(attack['attack_type'].upper())
            parameters = attack['parameters']
            parameters['_id'] = parameters['id']
            parameters.pop('id', None)

            #  Payload can be either base 2 or base 16 encoded.
            #  Automatically convert a payload to base 2 if needed
            if 'payload' in parameters.keys() and parameters['payload'][:2] == '0x':
                try:
                    hex_len = len(parameters['payload']) - 2
                    parameters['payload'] = bin(int(parameters['payload'],16))[2:].zfill(hex_len*4)
                except ValueError:
                    continue
            
            if 'payloads' in parameters.keys():
                try:
                    hex_len = len(parameters['payloads'][0]) - 2
                    parameters['payloads'] = [(bin(int(x,16))[2:].zfill(hex_len*4) if x[:2] == '0x' else x)for x in  parameters['payloads']]

                except ValueError:
                    continue
            
            if attack_type == AttackType.BASIC:
                parameters['attack_type'] = ImplementationType(parameters['implementation_type'])
                bia = Basic_injection_attack(**parameters)
                dataset = bia.build_dataset(dataset)

            elif attack_type == AttackType.DOS:
                dos = Dos_attack(**parameters)
                dataset = dos.build_dataset(dataset)

            elif attack_type == AttackType.DROP:
                drop = Drop_attack(**parameters)
                dataset = drop.build_dataset(dataset)

            elif attack_type == AttackType.FUZZY:
                parameters['attack_type'] = ImplementationType(parameters['implementation_type'])
                fuz = Fuzzy_injection_attack(**parameters)
                dataset = fuz.build_dataset(dataset)
            
            elif attack_type == AttackType.PROGRESSIVE:
                parameters['attack_type'] = ImplementationType(parameters['implementation_type'])
                prog = Progressive_injection_attack(**parameters)          
                dataset = prog.build_dataset(dataset)

            elif attack_type == AttackType.REPLAY: 
                parameters['attack_type'] = ImplementationType(parameters['implementation_type'])
                # Parse replacement dictionary if needed
                if 'replacements' in parameters:
                    replacements = {}
                    reps = parameters['replacements']
                    for rep in reps:
                        rep_type = ReplacementType(rep['replacement_type'])
                        if not 'parameters' in rep:
                            rep['parameters'] = {}
                        else:
                            # Convert hex payloads to binary
                            replacements_parameters = rep['parameters']
                            if 'payloads' in replacements_parameters:
                                if type(replacements_parameters['payloads']) == str and replacements_parameters['payloads'][:2] == '0x':
                                    hex_len = len(replacements_parameters['payloads']) - 2
                                    rep['parameters']['payloads'] = bin(int(replacements_parameters['payloads'],16))[2:].zfill(hex_len*4)
                                elif type(replacements_parameters['payloads']) == list:
                                    hex_len = len(replacements_parameters['payloads'][0]) - 2
                                    rep['parameters']['payloads'] = [(bin(int(x,16))[2:].zfill(hex_len*4) if x[:2] == '0x' else x)for x in replacements_parameters['payloads']]
                        replacements[(rep['start'], rep['end'])] = Replacement(rep_type, **rep['parameters'])

                    parameters['replacements'] = replacements
                    
                replay = Replay_attack(**parameters)
                dataset = replay.build_dataset(dataset)

            else:
                raise ValueError('Invalid attack type ' + attack_type)
        
            self.vulnerable_dataset = dataset
            
        return self.vulnerable_dataset


if __name__ == "__main__":
    parser = ArgumentParser(description='A tool to insert attacks into a CAN traffic dataset')
    parser.add_argument('-c', '--config_path', 
                            type=str,
                            help='The path of the config file')     
    parser.add_argument('-e', '--export_path',
                            type=str,
                            default='vulnerable.csv',
                            help='The path where to export the vulnerable dataset')
    parser.add_argument('--no_graphs', 
                            action='store_true',
                            default=False)
    args = parser.parse_args()

    path = args.config_path
    export_path = args.export_path
    graphs = not args.no_graphs

    if not os.path.isfile(path):
        raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), path)
        
    # Load attacck settings file
    with open(path) as f:
        data = json.load(f)

    try:
        dataset_name = DEIBVehicle(data['dataset'])
        dataset = load_dataset(dataset_name)
    except ValueError:
        # When importing from an external dataset, 
        #  be sure that indexes are sequential starting from 0
        dataset_path = data['dataset']
        dataset = load_dataset(path=dataset_path)

    ea = EnsambleAttack()
    final_dataset = ea.build_dataset(dataset, data['attacks'])

    if graphs:
        print("Preparing data visualization---")
        ea.visualize_changes()

    ea.export_dataset(path=export_path)