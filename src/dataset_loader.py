from enum import Enum
from datetime import datetime
from utils import Logger
import requests, os, tarfile
import pandas as pd
import numpy as np

class DEIBVehicle(Enum):
    ALFA_GIULIA = "C-1-AlfaRomeo-Giulia"
    OPEL_CORSA = "C-2-Opel-Corsa"
    MITSUBISHI = "T-1-Mitsubishi-FusoCanter"
    ISUZO = "T-2-Isuzu-M55"
    PIAGGIO = "T-3 Piaggio PorterMaxi"

max_exp = {
    DEIBVehicle.ALFA_GIULIA : 9,
    DEIBVehicle.OPEL_CORSA : 1,
    DEIBVehicle.MITSUBISHI : 1,
    DEIBVehicle.ISUZO : 2,
    DEIBVehicle.PIAGGIO : 3
}

class ColumnHeader(Enum):
        TIME = 'Time'
        CAN = 'Can#'
        ID = 'Id'
        DLC = 'Dlc'
        PAYLOAD = 'Payload'
        TAMPERED = 'IsTampered'

def load_dataset(vehicle=DEIBVehicle.ALFA_GIULIA, exp=1, to_datetime=False, add_tampered_column=True, verbose=True, path=None, dataset_folder='./datasets/'):
    """
    Return the target dataset as panda dataframe
    If the argument `vehicle` isn't passed, ALFA_GIULIA will be used.
    If the argument `exp` isn't passed, 1 will be used.

    If no parameters are passed, the first experiment of Alfa Giulia is retrieved

    Parameters
    ----------
    vehicle : enum, optional
        The vehicle's dataset you want to retrieve 

    exp: integer, optional
        The experiment number
    """
    assert type(vehicle) == DEIBVehicle
    assert type(add_tampered_column) == bool
    assert type(to_datetime) == bool
    assert type(verbose) == bool

    if exp != 'all':
        assert type(exp) == int
        assert exp > 0

    logger = Logger(verbose=verbose)

    if not os.path.exists(dataset_folder):
        os.mkdir(dataset_folder)

    header_list = ['Time', 'Can#', 'Id', 'Dlc', 'Payload']
    csv_file_path = dataset_folder + '/raw.csv'

    if path is None:
        
        target_paths = list()
        traces = list()

        exps = [exp] if exp != 'all' else [x for x in range(1, max_exp[vehicle])]

        for exp in exps:
            dataset_url = 'https://github.com/Cyberdefence-Lab-Murcia/ReCAN/raw/master/Data/%s/Exp-%d/raw.tar.gz' % (vehicle.value, exp)
            if vehicle == DEIBVehicle.ALFA_GIULIA and exp == 3:                     # For compliancy with strange specific structure
                dataset_url = dataset_url.replace('raw.tar.gz', 'raw.csv.tar.gz')
            target_path = dataset_folder + '%s_exp%d.tar.gz' % (vehicle.value, exp)
            target_paths.append(target_path)
            logger.print('%s(exp %d) selected' % (vehicle.value, exp))
            if not os.path.exists(target_path):
                response = requests.get(dataset_url, stream=True)
                logger.print('Getting file from GitHub..')
                if response.status_code == 200:
                    with open(target_path, 'wb') as f:
                        f.write(response.raw.read())
                        logger.print('..done')
                elif response.status_code == 404:
                    print('No experiment with the given id_exp(%d) for vehicle: %s' % (exp, vehicle.value))
                    print('Url was: %s' % dataset_url)
                    exit
                else:
                    print(response.status_code, 'An error occured during dataset retrieval')

            logger.print('Extracting..')
            filename = 'raw.csv' if exp != 3 else './raw.csv'
            a_trace = pd.read_csv(
                tarfile.open(target_path, 'r').extractfile(filename),
                sep=',',
                names=header_list  
            )
            logger.print('..done')
            traces.append(a_trace)

        trace = pd.concat(traces)

    else:
        assert type(path) == str
        logger.print('Reading dataset from file..')
        csv_file_path = path
        trace = pd.read_csv(csv_file_path, names=header_list)
        logger.print('..done')
    
    if to_datetime:
        logger.print("Converting timestamps..")
        trace['Time'] =  trace['Time'].apply(lambda x: datetime.fromtimestamp(x))
        logger.print("..done")

    # Add IsTampered column if necessary
    if add_tampered_column:
        trace['IsTampered'] = [0 for _ in range(trace.shape[0])]  
    
    return trace

if __name__ == "__main__":
    trace = load_dataset(path='/home/alenichel/Downloads/raw.csv')
    print('Total line: %d' %(len(trace)))