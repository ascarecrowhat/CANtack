from enum import Enum
from tqdm import tqdm
from pprint import pprint
import math
import numpy as np
import pandas as pd


class SIGN_TYPE(Enum):
    PHYSVAL = "PHYSVAL"
    COUNTER = "COUNTER"
    CRC = "CRC"
    BINARY = "BINARY"


def __pre_processing(payloads, dlc):
    bit_flip = [0 for _ in range(dlc * 8)]
    magnitude = [0 for _ in range(dlc * 8)]
    payload_len = len(payloads)

    for i in range(1, len(payloads)):
        payload = payloads[i]
        previous = payloads[i - 1]
        for j in range(dlc * 8):
            if payload[j] != previous[j]:
                bit_flip[j] = bit_flip[j] + 1

    for i in range(8 * dlc):
        bit_flip[i] = bit_flip[i] / payload_len
        magnitude[i] = math.ceil(math.log10(bit_flip[i])) if bit_flip[i] != 0 else float('-inf')

    return bit_flip, magnitude


def __phase1(magnitude, dlc):
    ref = list()
    prev_magnitude = magnitude[0]
    ix_s = 0

    for ix in range(dlc * 8):
        if magnitude[ix] < prev_magnitude:
            ref.append((ix_s, ix))  # remember python indexes rules
            ix_s = ix
        # skip a bit that never flips
        if math.isinf(magnitude[ix]):
            ix_s += 1
        prev_magnitude = magnitude[ix]

    # if after the last signal all the magnitudes are not -inf
    if ix_s != dlc * 8:
        ref.append((ix_s, dlc * 8))
    return ref


def __match_counter(bit_flip):
    candidate = 0
    for i in range(1, len(bit_flip)):
        if math.isclose(bit_flip[i], 2 * bit_flip[i - 1], rel_tol=0.01):
            if math.isclose(bit_flip[i], 1.0, rel_tol=0.001):
                return candidate, i + 1
        else:
            candidate = i
    return -1, -1


def __phase2(ref, bit_flip, magnitude):
    r_ref = list()
    for sign in ref:
        ix_start = sign[0]
        ix_end = sign[1]

        # Check if there is an empty block added by a previous iteration
        if (ix_start == ix_end):
            continue

        # Check if the block is a binary flag
        if (ix_start + 1 == ix_end):
            r_ref.append([ix_start, ix_end, SIGN_TYPE.BINARY])
            continue

        mgt = magnitude[ix_start:ix_end]

        # Check if there is a counter
        start_ctr, end_ctr = __match_counter(bit_flip[ix_start:ix_end])
        if start_ctr >= 0 and end_ctr >= 0:
            # Case: all the block is a counter
            if start_ctr == 0 and end_ctr == (ix_end - ix_start):
                r_ref.append([ix_start, ix_end, SIGN_TYPE.COUNTER])
                continue
            else:
                # Case: not all the block is a counter
                #       then the part before, and the part after
                #       need to be checked again
                r_ref.append([ix_start + start_ctr, ix_start + end_ctr, SIGN_TYPE.COUNTER])
                ref.append((ix_start, ix_start + start_ctr))
                ref.append((ix_start + end_ctr, ix_end))
                continue

        # Check if there is a CRC
        found_crc = False
        for start_crc in range(ix_start, ix_end):
            mu = np.mean(bit_flip[start_crc:ix_end])
            std = np.std(bit_flip[start_crc:ix_end])
            if sum(mgt[start_crc:ix_end]) == 0:
                if 0.5 - std <= mu and mu <= 0.5 + std:
                    r_ref.append([start_crc, ix_end, SIGN_TYPE.CRC])
                    ref.append((ix_start, start_crc))
                    found_crc = True
                    break
        # If the block is not a BINARY, not a COUNTER, and not a CRC, then
        if not (found_crc):
            r_ref.append([ix_start, ix_end, SIGN_TYPE.PHYSVAL])
    return r_ref


def export_results(trace, results, export_path=None):
    assert type(results) == dict

    all_rows = list()
    row_counter = 0
    for index, row in trace.iterrows():
        if row_counter % 50000 == 0:
            print("Row %d out of %d (%f%%)" % (row_counter, trace.shape[0], row_counter / trace.shape[0] * 100))
        counter = 0
        for sign in results[row['Id']]:
            new_row = [
                row['Time'],
                row['Id'],
                sign[0],
                sign[1],
                row['Can#'],
                sign[2].value,
                'V%s' % (str(counter)),
                int(row['Payload'][sign[0]:sign[1]], 2)
            ]
            all_rows.append(new_row)
            counter += 1
        row_counter += 1

    print("Building dataframe...")
    df = pd.DataFrame(all_rows,
                      columns=('Time', 'Id', 'StartBit', 'EndBit', 'Can#', 'Datatype', 'Variable', 'Value'))
    print("..done")

    pprint(df)

    if export_path != None:
        print("Exporting to file..")
        df.to_csv(export_path, index=False, header=True)
        print("...done")

    return df


def read(trace, verbose=True, full_result=False):
    ids = set(trace['Id'].tolist())
    ids = list(ids)

    if verbose:
        print("""

        Number of lines: %d
        Number of ids: %d

        """ % (trace.shape[0], len(ids)))

    subtraces = list()
    for _id in ids:
        subtrace = trace[trace['Id'] == _id]
        subtraces.append(subtrace)

    assert len(subtraces) == len(ids)

    results = dict()
    bit_flips = dict()
    magnitudes = dict()

    for i in (tqdm(range(len(subtraces))) if verbose else range(len(subtraces))):
        subtrace = subtraces[i]
        payloads = subtrace['Payload'].tolist()
        DLC = subtrace['Dlc'].tolist()[0]

        bit_flip, magnitude = __pre_processing(payloads, DLC)

        ref = __phase1(magnitude, DLC)

        r_ref = __phase2(ref, bit_flip, magnitude)

        results[ids[i]] = r_ref
        bit_flips[ids[i]] = bit_flip
        magnitudes[ids[i]] = magnitude

    if not full_result:
        return results

    return results, bit_flips, magnitudes