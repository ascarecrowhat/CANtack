# CANtack, synthetic CAN attacks generator

CANtack is a tool that synthetizes an attack Controller Area Network(CAN) dataset from a real normal CAN dataset.

### Attacks
The user has the possibility to decide between implementing an injection attack or a masquerade attack.
The injection attack adds the malicious packets into the dataset whereas the masquerade attack changes the already existing frames, performing an spoofing attack.


The attacks implemented are:
* **Basic attack** - Return the original dataset with the addition or change of the specified number of packets. All the injected or masquerade frames will have the same payload. 
* **Replay attack** - Return the original dataset with the addition of the specified number of packets sniffed from the previous traffic at the specified time point, either unchanged or with
        some specified replacement. In order to do a replacement it is needed to specify the specific bits. 
        Types of replacements:
    * *Payloads* - Specify the list of the binary strings that will be replaced into the chosen range. The length of the strings needs to match the length of the ranges. The length of the list
                        needs to match the number of injected packets
    * *Fuzzy* - Substitute random bits inside the specified range
    * *Min* - Replace all the bits in the range with their minimum value detected in the dataset
    * *Max* - Replace all the bits in the range with their maximum value detected in the dataset
    * *Countinous change* - to choose the final payload that will have the signal in the specified bit range. The payloads of the tampered packets will start from the
            last sniffed value before the attack and increase or decrease continuosly until the specified value is reached 
* **Fuzzy attack** - Inject or masquerade frames with a random payload in the original dataset. The ID is specified. It could be specified a fuzzy intelligent attack which only put random data into the signals of the frame. 
* **Progressive attack** - Inject or masquerade packets with different payloads. The payloads need to be specified.
* **Drop attack** - Delete a specified number of packets of a concrete ID in an specified moment. 
* **Denial of Service** - During an amount of time specified of the original dataset, fill the bus with the maximum number of frames allowed by the speed of the bus. The ID and the payload can be choosen, by default the ID is zero and the payload is filled with '1'.
### Other functions
In the project there are also other useful functions:
 * **Read function** - Function that read the frames of a concrete dataset and is able to to find the signals inside the payloads. Moreover it classifies the type of signals between physical value, binary value, counter and CRC.
 For more information of the algorithm click [here](https://ieeexplore.ieee.org/document/8466914).
 * **Multiple attack function ** - Function that automatizes the attack tool, making a percentage of attacks respect to the normal dataset. This is the function "random_fill" inside the file attack_generator.

## Getting Started 

The first step is to download the project and decompress it.

### Prerequisites
In order to run the project it is necessary to have installed previously python 3. In order to install python click [here](https://www.python.org/downloads/).
Furthermore, the following libraries need to be installed:
* argparse
* errno
* json
* math
* numpy
* os
* pandas
* pprint
* random
* tqdm
* warnings

For installing libraries in python usually is done by:
```
pip3 install library
```


## Running the tool
In order to run the tool there are needed two more arguments: the path of the configuration file and the path for saving the created dataset. The path of the exported dataset is optional, in case of not having any it will not be saved.

An example of running the tool is:
````
main.py -c pathConfigFile -e pathExportFile
````

## Configuration file
In the configuration file it is specified the normal dataset and the attacks performed in it.
The configuration file is a json file with two fields: dataset and the attacks.

In the attacks field, it is specified each attack in a subfield. It is specified the attack's name, the type of attack and the parameters needed for making the attack.
Depending on the type of the attack performed there are needed different parameters to be specified.

The common parameters are:

Common Parameters |
------------- |
id            |
beginning_time_delta|
injected_packets|
implementation_type|
injection_rate|
average_interval|



The following table specifys the specific parameters for each attack:

Basic Attack  | Replay attack | Fuzzy attack | Progressive attack | Drop attack | DoS attack
------------- | ------------- | ------------- | ------------- | ------------- | ------------- |
 -       |    sniffing_time_delta |smart_fuzzying|payloads|dropped_packets|duration|
 -       |    pattern_packets |bit_ranges|-|-|-|
 -       |    is_random_start |seed|-|-|-|
 -       |    replacements |-|-|-|-|
 
 It should be mentioned that inside the parameters replacement of replay attack can have the fields specified in the Attacks section.
 
### Examples of configurations
There are some examples of configurations inside the folder:
````
/attack_tool/src/example_configurations
````
### Datasets
By default the real datasets used are from ReCAN. It is needed to specify the name of the dataset, in other case the dataset by default is: C-1-AlfaRomeo-Giulia. For more information click [here](https://data.mendeley.com/datasets/76knkx3fzv/2).
It can also be used the dataset that the user wants by specifying its path on the configuration file, in the dataset field.
Moreover, in case that the database of ReCAN is wanted, it is also needed connection to internet because it downloads the dataset from Github.


## Authors

* **Carlo Alberto Pozzoli** 
* **Alessandro Nichelini** 
* **Teresa Costa Cañones** 



