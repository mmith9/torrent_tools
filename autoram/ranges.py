import configparser
import portion as P
import logging
import numpy as np


logging.config.fileConfig('logging.conf')
logger = logging.getLogger(__name__)
config = configparser.ConfigParser()
config.read('autoram.ini')


class IntInterval(P.AbstractDiscreteInterval):
    _step = 1
II = P.create_api(IntInterval)


def get_block_ranges(file, blocknum):
    block_ranges = II.closedopen(
        max(0, file['piece_size']*blocknum + file['pieces_offset']),
        min(file['piece_size']*(blocknum + 1) +
            file['pieces_offset'], file['size'])
    )
    block_size = block_ranges.upper - block_ranges.lower +1
    return block_ranges, block_size

def estimate_gain_from_repair(target_file, src_files):
    ranges_needed = target_file['ranges_needed']
    gain = ranges_needed
    for file in src_files:
        ranges_needed = ranges_needed - file['ranges_complete']

    gain = gain - ranges_needed
    return gain, ranges_needed
 
def size_to_dib(size):
    index = 0
    new_size = int(size / 1024)
    while new_size > 1024:
        new_size = int(new_size / 1024)
        index += 1
    new_size = str(new_size) + [' KiB', ' MiB', ' GiB', ' TiB'][index]
    return new_size

def sum_ranges(ranges):
    the_sum = 0
    for rang in ranges:
        the_sum += rang.upper-rang.lower+1
    return the_sum

def shift_ranges(ranges, distance):
    ranges = ranges.apply(lambda x: (x.left, x.lower + distance, x.upper+distance, x.right))
    return ranges

