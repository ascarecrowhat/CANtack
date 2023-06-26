from dataset_loader import load_dataset
import pandas as pd
import numpy as np
import warnings

#Values of the frames counting the bits between packets (inter-arrival)
MIN_FRAME_LENGTH = 47
MIN_EXTENDED_FRAME_LENGTH = 67
THRESHOLD_ERROR = 0.000005


def calculate_average_interval(dataset, id):
    id_times = dataset.loc[dataset['Id'] == id, 'Time']
    ind = id_times.index
    if len(ind) > 1:
        interval_id = id_times[ind[-1]] - id_times[ind[0]]
        return interval_id/(len(id_times)-1)


def inject_function(dataset, id, payloads, beginning_time_delta, injection_rate, average_interval = None, check_bus = False, bus_speed = 1e6):
    """
        Return the original dataset with the addition of the specified packets

        This function must be able to provide the most general injection attack for a single id and will be called by the specific attack
        functions

        Parameters
        ----------
        dataset: pandas.Dataframe
            The original dataset

        id: string
            The id of the injected packets as an hexadecimal string

        payloads: list[string]
            The payloads of the injected packets as binary strings, the number of injected packets is defined by the length of the list

        beginning_time_delta: int
            The time difference in milliseconds between the timestamp of the first message in the dataset (in seconds from 1st January 1970) and
            the beginning of the injection
        
        injection_rate: integer
            The rate of injection of packets with refer to the average packet inter-arrival time of the id. In case of not having packets with such
            id in the database, it is the percentage of the bus to be filled
            
        bus_speed: float
            The bus speed in bps.
            
    """
    #Checks the inputs
    assert type(dataset) == pd.DataFrame
    assert type(payloads) == list
    assert type(bus_speed) == float
    assert type(beginning_time_delta) == int or type(beginning_time_delta) == float
    assert beginning_time_delta > 0
    assert type(bus_speed) == int or type(bus_speed) == float

    for payload in payloads:
        try:
            int(payload, 2)
        except ValueError:
            raise ValueError('Payload must be base 2 encoded')
    try:
        int(id,16)
    except ValueError:
        raise ValueError('Id must be base 16 encoded')

    assert type(beginning_time_delta) == int or type(beginning_time_delta) == float
    assert type(injection_rate) == int or type(injection_rate) == float

    # Number of injected packets
    injected_packets = len(payloads)
    # Get the average interval between packets of the Id and the period of injected messages from it
    id_dataset = dataset[(dataset['Id'] == id)]
    #See if there are packets with this id in the dataset
    if id_dataset.shape[0]==0:
        warnings.warn('There is no id:%s in the initial dataset. The injection rate is going to behave as the percentage of the bus to be filled with injected messages' % id)
        Dlc=np.ceil(len(payloads[0])/8)
        # Injected on the can of the first. TODO: make the user decide which can use
        can_num = dataset['Can#'].tolist()[0]
    else:
        #Calculate the Length packet. TODO: find a better way of the packet time
        Dlc = id_dataset['Dlc'].tolist()[0]
        can_num = id_dataset['Can#'].tolist()[0]

    if len(id)==3:
        packet_length=Dlc*8+MIN_FRAME_LENGTH
    else:
        packet_length=Dlc*8+MIN_EXTENDED_FRAME_LENGTH

    packet_time = packet_length/bus_speed

    if average_interval is None:
        injection_period = packet_time*(100/injection_rate)
    else:
        injection_period = average_interval/injection_rate

    #Check the maximum injection rate
    if injection_period<packet_time:
        injection_period=packet_time
        real_injection_rate=(average_interval/injection_period)
        warnings.warn('The injection rate is higher than the available throughput. The maximum injection rate is %d' % real_injection_rate)


    init_ind=dataset.index
    interval = dataset['Time'][init_ind[-1]] - dataset['Time'][init_ind[0]]
    if beginning_time_delta > interval:
        raise ValueError('Beginning time delta must be lower than the covered period from the dataset (%d)' % interval)

    # Calculate timestamps of the injected messages adding a white noise to the expected injection times
    initial_timestamp = dataset['Time'][init_ind[0]] + beginning_time_delta
    final_timestamp = initial_timestamp + injection_period * (injected_packets - 1)
    new_timestamps = np.linspace(initial_timestamp, final_timestamp, num=injected_packets)

    # TODO: define standard deviation better
    std = injection_period/500
    noise = np.random.normal(0, std, injected_packets)
    new_timestamps = np.add(new_timestamps, noise)

    # Separate not affected messages not to have to sort the whole dataset
    previous_messages = dataset[dataset['Time'] <= new_timestamps.tolist()[0]]
    next_messages = dataset[dataset['Time'] >= (new_timestamps.tolist()[-1]+packet_time)]
    start = previous_messages.index[-1] + 1
    if next_messages.shape[0]==0:
        current_messages = dataset[start:]
    else:
        end = next_messages.index[0]
        current_messages = dataset[start:end]

    # Add injected messages to the dictionary and to the current DataFrame
    data_dictionary = {'Time': new_timestamps, 
                        'Can#': can_num,
                        'Id': id, 
                        'Dlc': Dlc, 
                        'Payload': payloads,
                        'IsTampered': 1}

    current_messages = current_messages.append(pd.DataFrame.from_dict(data_dictionary), ignore_index=True)

    # As the injected messages were appended, sort by timestamp to obtain the correct order
    current_messages.sort_values(by='Time', inplace=True)

    #Put new indices for later check of the throughput
    current_messages= current_messages.reset_index(drop=True)

    #Check that the inserted messages don't over throughput
    indices_to_drop = []

    #Do the window

    #Checks
    size_packets=current_messages['Dlc'].tolist()
    id_windows=current_messages['Id'].tolist()
    tampered_m=current_messages['IsTampered'].tolist()
    arrival_pack=current_messages['Time'].tolist()
    indices_window=current_messages.index

    last_quit=False
    # Check drop the ones for the time interval wrong, this perfoms an error of 0.076% due to float limitations
    if check_bus:
        for j in range(1,len(arrival_pack)):

            if last_quit:
                last_quit = False
                #Check if the both packets are or not attack packet
                if ((tampered_m[j] == 0) & (tampered_m[prev] == 0)):
                    continue
                #Packet_time of the current packet
                if len(id_windows[prev]) == 3:
                    packet_time = ((size_packets[prev] * 8 + MIN_FRAME_LENGTH) / bus_speed)
                else:
                    packet_time = ((size_packets[prev] * 8 + MIN_EXTENDED_FRAME_LENGTH) / bus_speed)

                inter_arrival = arrival_pack[j] - arrival_pack[prev]

                if inter_arrival < (packet_time-THRESHOLD_ERROR):
                    if (int(id_windows[j], 16) >= int(id_windows[prev], 16)):
                        indices_to_drop.append(indices_window[j])
                        last_quit = True
                    else:
                        indices_to_drop.append(indices_window[prev])
                continue
            if ((tampered_m[j]==0) & (tampered_m[j-1]==0) ):
                continue
            if len(id_windows[j-1]) == 3:
                packet_time = ((size_packets[j-1] * 8 + MIN_FRAME_LENGTH) / bus_speed)
            else:
                packet_time = ((size_packets[j-1] * 8 + MIN_EXTENDED_FRAME_LENGTH) / bus_speed)
            inter_arrival=arrival_pack[j]-arrival_pack[j-1]
            if inter_arrival<(packet_time-THRESHOLD_ERROR):
                # Drop the packet with the id higher
                if(int(id_windows[j],16)>=int(id_windows[j-1],16)):
                    indices_to_drop.append(indices_window[j])
                    last_quit=True
                    prev=j-1
                else:
                    indices_to_drop.append(indices_window[j-1])
        #Drop only the attack messages
        current_messages=current_messages.drop(labels=indices_to_drop)

    # Reconstruction of the dataset, ignore_index=True means that the index column of the Dataframe will have the correct values
    previous_messages = previous_messages.append(current_messages, ignore_index=True).append(next_messages, ignore_index=True)

    # Some assertion about the results
    # TODO: add more assertion check ? 
    assert dataset.shape[0] == previous_messages.shape[0] - injected_packets + len(indices_to_drop)

    return previous_messages

if __name__ == "__main__":
    dataset = load_dataset()

    # Some stats, you can ignore them

    # BUS frequency in hertz
    FREQUENCY = 1e6
    PERIOD = 1/FREQUENCY

    # min length in bits of a frame, including interframe space and without payload and stuffing
    MIN_FRAME_LENGTH = 47
    MIN_EXTENDED_FRAME_LENGTH = 67

    # Time Needed for a typical 64 bits packet transmission (0.111ms)
    packet_time = (MIN_FRAME_LENGTH + 64) * PERIOD
    print("redicted packet transmission time: " + str(packet_time))

    # Average inter-arrival time (0.379ms)
    inter = (dataset['Time'][dataset.shape[0] -1] - dataset['Time'][0])/(dataset.shape[0] - 1)
    print("Average inter-arrival time: " + str(inter))

    id = '0F0'

    # The period for id 0F0 is 10ms
    indices = dataset[dataset['Id'] == id].index
    inter = (dataset[dataset['Id'] == id]['Time'][indices[-1]] - dataset[dataset['Id'] == id]['Time'][indices[0]])/(len(indices)-1)
    print("Average inter-arrival time for Id " + id + ": " + str(inter))

    # To succeed in the attack we need an injection rate between 20 and 100
    injection_rate = 20
    injection_period = inter/injection_rate
    # Number of injected packets
    injected_packets = 30
    # Time the injected packet is send, initialized at the attack's initial time
    injection_time_delta = 1000

    payload = 'FFFFFFFFFFFFFFFF'
    payloads = [bin(int(payload, 16))[2:]]*30
    id="0F0"
    time = dataset['Time'][0] + injection_time_delta

    res = inject_function(dataset,
                            id, 
                            payloads, 
                            injection_time_delta, 
                            1,
                            bus_speed = FREQUENCY)

    print(res.loc[(res['Time'] > time) & (res['Id'] == id)])