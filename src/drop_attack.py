import pandas as pd
import numpy as np
from dataset_loader import load_dataset, ColumnHeader
from basic_attack import Attack

class Drop_attack(Attack):

    attack_parameters = dict()

    def __init__(self, _id, beginning_time_delta, dropped_packets):
        """
        Initialize the object

        Parameters
        ---------

        id: string
            The id of the dropped packets as an hexadecimal string

        beginning_time_delta: float
            The time difference in seconds between the timestamp of the first message in the dataset (in seconds from 1st January 1970) and
            the beginning of the drop

        dropped_packets: integer
            The number of dropped packets
        """
        super().__init__()
        assert type(_id) == str
        assert type(beginning_time_delta) == int or type(beginning_time_delta) == float
        assert type(dropped_packets) == int

        self.attack_type = 'DROP'
        self.name = 'drop%s' % id(self)

        self.parameters = dict()
        self.parameters['id'] = _id
        self.parameters['beginning_time_delta'] = beginning_time_delta
        self.parameters['dropped_packets'] = dropped_packets

    def build_dataset(self, dataset):
        """
        Return the original dataset without the specified packets

        Parameters
        ----------
        dataset: pandas.Dataframe
            The original dataset
        """
        assert type(dataset) == pd.DataFrame

        index = dataset.index
        initial_timestamp = dataset['Time'][index[0]] + self.parameters['beginning_time_delta']

        dataset = dataset.drop(dataset.loc[(dataset['Time'] > initial_timestamp) & (dataset['Id'] == self.parameters['id'])][0:self.parameters['dropped_packets']].index)
        try:
            next_packet_index = dataset.loc[(dataset['Id'] == self.parameters['id']) & (dataset['Time'] > initial_timestamp)].index[0]
            dataset['IsTampered'][next_packet_index] = 1
        except:
            pass

        self.vulnerable_dataset = dataset

        # Reset index to correct values without the dropped packets
        self.vulnerable_dataset.index = pd.RangeIndex(0, len(self.vulnerable_dataset.index))
        
        return self.vulnerable_dataset

    def toJSON(self):
        dict_representation = dict()
        dict_representation['name'] = self.name
        dict_representation['attack_type'] = self.attack_type
        dict_representation['parameters'] = self.parameters

        return dict_representation

    def __str__(self):
        return str(self.toJSON())

if __name__ == "__main__":
    dataset = load_dataset()
    da = Drop_attack('0F0', 1000, 30)
    r = da.build_dataset(dataset)
    #print(da.vulnerable_dataset)

    from pprint import pprint 
    pprint(da.toJSON())