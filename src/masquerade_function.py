from dataset_loader import load_dataset
import pandas as pd
import numpy as np
import warnings
from tqdm import tqdm

def masquerade_function(dataset, id, beginning_time_delta, replacements, verbose = True):
    """
        Return the original dataset where the set of given payloads is substituted to the packets on the bus starting from the given time point, keeping
        the same timestamp. All others packets are kept untouched.

        This function must be able to provide the most general masquared attack for a single id and will be called by the specific attack
        functions.

        Parameters
        ----------
        dataset: pandas.Dataframe
            The original dataset

        id: string
            The id of the injected packets as an hexadecimal string

        injection_time_delta: float
            The time difference in milliseconds between the timestamp of the first message in the dataset (in seconds from 1st January 1970) and
            the beginning of the injection
        
        replacements: dict( couple(int, int) -> list[string]]
            A dict containing the couple representing bit intervals as key and a list of payloads to replace as value.
    """
    # Parameters type assertion
    assert type(dataset) == pd.DataFrame
    assert type(replacements) == dict
    assert len(replacements.keys()) > 0
    if id not in list(set(dataset['Id'].tolist())):
        raise ValueError('No messages with the given id (%s) in the dataset' %id)
    for bit_range in replacements.keys():
        assert type(bit_range) == tuple
        starting_bit = bit_range[0]
        ending_bit = bit_range[1]
        assert starting_bit >= 0
        assert ending_bit <= 64
        if starting_bit > ending_bit:
            raise ValueError('Starting bit has to be lower than ending bit for each given bit range')
    for payloads in replacements.values():
        assert type(payloads) == list
    
    # Calculate first dataset timestamp and starting timestamp of the attack
    indexes = dataset.index
    initial_timestamp = dataset['Time'][indexes[0]]
    final_timestamp = dataset['Time'][indexes[-1]]
    interval = final_timestamp - initial_timestamp 
    
    # Check beggining_time_delta parameter
    if beginning_time_delta > interval :
        raise ValueError('Beginning time delta must be lower than the covered period from the dataset (%d)' % interval)
    
    # Some information retriaval
    beginning_ot_attack_timestamp = initial_timestamp + beginning_time_delta
    n_of_packets = len(list(replacements.values())[0]) 
    id_dataset = dataset[dataset['Id'] == id]
    indices = id_dataset.index
    can_num = id_dataset['Can#'][indices[0]]
    dlc = id_dataset['Dlc'][indices[0]]

    for payloads in replacements.values():
        payload_len = len(payloads[0])
        for payload in payloads:
            assert type(payload) == str
            try:
                int(payload, 2)
            except ValueError:
                raise ValueError('Payloads must be base 2 encoded')
            if len(payload) != payload_len:
                raise ValueError('All given payloads must have the same length')

    for bit_range in list(replacements.keys()):
        starting_bit = bit_range[0]
        ending_bit = bit_range[1]
        payload_len = len(replacements[bit_range][0])
        if payload_len != ending_bit - starting_bit:
            raise ValueError('Provided payloads length (%d) must comply with the payloads section length to replace %s' % ((payload_len), str(bit_range)))


    attack_dataset = id_dataset.loc[id_dataset['Time'] >= beginning_ot_attack_timestamp].head(n_of_packets)
    if sum(attack_dataset['IsTampered']) != 0:
        warnings.warn('Attacks are overlapping')
    attack_indexes = attack_dataset.index
    old_payloads = attack_dataset['Payload'].tolist()

    if len(old_payloads) < n_of_packets:
        warnings.warn('NOT ENOUGH PACKET, returning original dataset.')
        return dataset

    # If not all the payloads has to be replaced
    new_payloads = list()
    no_change = True
    for i in range(n_of_packets):
        new_payload = list(old_payloads[i])
        for bit_range in replacements.keys():
            payloads = replacements[bit_range]
            starting_bit = bit_range[0]
            ending_bit = bit_range[1]
            if no_change and new_payload[starting_bit:ending_bit] != list(payloads[i]):
                no_change = False
            new_payload[starting_bit:ending_bit] = payloads[i]
        new_payload = "".join(new_payload)
        new_payloads.append(new_payload)
        
    if no_change:
        if verbose:
            tqdm.write('The attack on id {} was not inserted because it would not change the dataset'.format(id))
        return dataset
    dataset.loc[attack_indexes, 'Payload'] = new_payloads
    dataset.loc[attack_indexes, 'IsTampered'] = 1


    return dataset    

if __name__ == "__main__":
    dataset = load_dataset()
    bit_range = (0, 5)

    replacements = {
                    (15, 20): ['0'*5] * 10,
                    }   
    res = masquerade_function(dataset, '1FA', 1000, replacements)
    print(res)

    res = res[(res['Id'] == '1FA') & (res['IsTampered'] == 1)]
    print(res)