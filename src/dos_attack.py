import pandas as pd
import numpy as np
from dataset_loader import load_dataset, ColumnHeader
from basic_attack import Attack
from injection_function import inject_function

MIN_FRAME_LENGTH = 47
MIN_EXTENDED_FRAME_LENGTH = 67

class Dos_attack(Attack):
    attack_parameters = dict()

    def __init__(self, injection_time_delta, duration, bus_speed=0.5e6, percentage_bus=100 , _id = '000', payload='00000000'):
        super().__init__()
        assert injection_time_delta > 0
        assert duration > 0
        #Check the payload is in binary
        try:
            int(payload, 2)
        except ValueError:
            raise ValueError('Payload must be base 2 encoded')
        #Check the id is in hexadecimal
        try:
            int(_id, 16)
        except ValueError:
            raise ValueError('Id must be base 16 encoded')

        self.attack_name = 'dos%s' % id(self)
        self.attack_type = 'DOS'
        self.parameters = dict()
        self.parameters['injection_time_delta'] = injection_time_delta
        self.parameters['duration'] = duration
        self.parameters['bus_speed'] = bus_speed
        self.parameters['percentage_bus'] = percentage_bus
        self.parameters['id'] = _id
        self.parameters['payload'] = payload

    # Values of the frames counting the bits between packets (inter-arrival)

    def build_dataset(self, dataset):
        """
        Return the original dataset with the requested DoS attack

        Parameters
        ----------
        dataset: pandas.Dataframe
            The original dataset

        injection_time_delta: float
            The time difference in seconds between the timestamp of the first message in the dataset (in seconds from 1st January 1970) and
            the beginning of the DoS

        duration: float
            The duration of the attack in seconds
        bus_speed: int
            The bus speed in bps.
        percentage_bus: float
            The percentage of the attack, being 100 the bus totally saturated bus with the injection of the new packets
        
        id: string, optional
            The id of the injected packets as an hexadecimal string. Usually id '0x0' is used to win arbitration, we may decide to not have this
            parameter and use only the default id

        payload: string, optional
            The payload of the injected packets as hexadecimal string, not really important for this attack, we may decide to not have this parameter
        
    """
        assert type(dataset) == pd.DataFrame

        indices = dataset.index
        id = self.parameters['id']
        payload = self.parameters['payload']

        if len(id) <= 3:
            packet_length = len(payload)  + MIN_FRAME_LENGTH
            packet_time = (packet_length) / self.parameters['bus_speed']
        else:
            packet_length = len(payload) + MIN_EXTENDED_FRAME_LENGTH
            packet_time = (packet_length) / self.parameters['bus_speed']

        packet_interarrival=packet_time*(self.parameters['percentage_bus']/100)
        dataset_id=dataset.loc[(dataset['Id']==id) & (dataset['IsTampered'] == 0)]
        if dataset_id.shape[0]==0:
            injection_rate=self.parameters['percentage_bus']
        else:
            indices_id=dataset_id.index
            interval = dataset_id['Time'][indices_id[-1]] - dataset_id['Time'][indices_id[0]]
            average_interval = interval / (len(indices) - 1)
            injection_rate=int(np.round((average_interval/packet_interarrival-1)*100))

        #Compute the number of injected packets in the period.
        # The +1 is done in order to fill the entire duration of the DoS
        injected_packets=np.ceil(self.parameters['duration']/packet_interarrival)+1
        payloads=[payload]*int(injected_packets)

        self.vulnerable_dataset = inject_function(dataset, id, payloads, self.parameters['injection_time_delta'], injection_rate, bus_speed = self.parameters['bus_speed'], check_bus = True)

        return self.vulnerable_dataset

if __name__ == "__main__":
    time_delta = 900
    duration=1.1
    dos_a = Dos_attack()
    time = 50

    dataset = load_dataset()
    a =dos_a.build_dataset(dataset, time_delta, duration)
    error_dataset=dos_a.vulnerable_dataset[((dos_a.vulnerable_dataset['Time'] > time) & (dos_a.vulnerable_dataset['Time'] < time+duration)) & (dos_a.vulnerable_dataset['Id']!="000") ]
    #dos_a.visualize_changes(export=True)
    changed_data_set=dos_a.vulnerable_dataset[((dos_a.vulnerable_dataset['Time'] > time) & (dos_a.vulnerable_dataset['Time'] < time+duration))]
    error=error_dataset.shape[0]/changed_data_set.shape[0]
    print('The error is of %f' % error)

