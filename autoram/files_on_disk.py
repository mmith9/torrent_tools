#!/usr/bin/env python -u

import configparser
import hashlib
import logging
import logging.config
import os
import shutil

import numpy as np
from autoram.ranges import II, get_block_ranges

logging.config.fileConfig('logging.conf')
logger = logging.getLogger(__name__)

config = configparser.ConfigParser()
config.read('autoram.ini')
buffer_size = config.getint('behaviour', 'buffer_size') * 1024*1024


def extend_file(full_path_client, desired_size):
  # logger.debug('Extending to %s bytes, %s', desired_size, full_path_client)

    try:
        physical_size = os.path.getsize(full_path_client)
    except Exception as err:
        logger.error(err)
        return False

    difference = desired_size - physical_size
    if difference <= 0:
        logger.error('File bigger than desired size %s bytes %s',
                     desired_size, full_path_client)
        return False

    # logger.debug('Opening %s', full_path_client)
    try:
        with open(full_path_client, 'r+b') as fh:
            fh.seek(physical_size)
            while difference > buffer_size:
                fh.write(bytearray(buffer_size))
                difference -= buffer_size
            if difference > 0:
                fh.write(bytearray(difference))
    except Exception as err:
        logger.error(err)
        return False

    try:
        new_physical_size = os.path.getsize(full_path_client)
    except Exception as err:
        logger.error(err)
        return False

    if new_physical_size != desired_size:
        logger.critical('Extending to %s failed, got %s, on %s',
                        desired_size, new_physical_size, full_path_client)
        return False

    return True


def verify_and_fix_physical_file(file):
    path = file['full_path_client']
    # logger.debug('Checking phys file %s>%s', file['debug'], path)
    try:
        if not os.path.isfile(path):
            file['dummy'] = 'dummy'
            # logger.debug('dummy file found: %s', file['debug'])
            return True
        file['dummy'] = 'real'
        f_size = os.path.getsize(file['full_path_client'])
    except Exception as err:
        logger.error(err)
        return False

    if f_size < file['file'].size:
        if not extend_file(file['full_path_client'], file['file'].size):
            return False
    return True


def is_physical_file_unique(newfile, files):
    try:
        if not os.path.isfile(newfile['full_path_client']):
          # logger.debug('file does not exist, so its unique %s',
          #               newfile['filename'])
            return True

        for file in files:
            if newfile['path_server'] == file['path_server']:
                return False
            if not os.path.isfile(file['full_path_client']):
                continue
            if os.path.samefile(newfile['full_path_client'], file['full_path_client']):
                return False

        return True

    except Exception as err:
        logger.error('cant verify uniqueness of %s', newfile['filename'])
        logger.error(err)
        return False


def read_ranges(file, ranges):
    if len(ranges) > 1 or not ranges:
        return False
    try:
        with open(file['full_path_client'], 'rb') as fh:
            fh.seek(ranges.lower)
            data = fh.read(ranges.upper - ranges.lower + 1)
        block = np.frombuffer(data, dtype=np.ubyte)
        return block
    except Exception as err:
        logger.error('read ranges fail')
        logger.error(err)
        return False


def read_block(file, blocknum):
    block_ranges, block_size = get_block_ranges(file, blocknum)
    try:
        with open(file['full_path_client'], 'rb') as fh:
            fh.seek(block_ranges.lower)
            data = fh.read(block_size)
        block = np.frombuffer(data, dtype=np.ubyte)
        return block
    except Exception as err:
        logger.error('read block fail')
        logger.error(err)
        return False


def write_block(file, blocknum, data):
    block_ranges, block_size = get_block_ranges(file, blocknum)
    if len(data) != block_size:
        logger.error('write block size mismatch')
        return False
    try:
        with open(file['full_path_client'], 'rb+') as fh:
            fh.seek(block_ranges.lower)
            if isinstance(data, np.ndarray):
                fh.write(data.tobytes())
            else:
                fh.write(data)
        return True
    except Exception as err:
        logger.error('write block fail')
        logger.error(err)
        return False


def swap_files_inplace(file1, file2):
    temp_file = os.path.join(config['client']['qbt_tempdir'], 'temp_swap_file')
    try:
        shutil.move(file1['full_path_client'], temp_file)
        shutil.move(file2['full_path_client'], file1['full_path_client'])
        shutil.move(temp_file, file2['full_path_client'])

    except Exception as err:
        logger.critical('Inplace swap FAIL')
        logger.critical('file1 %s', file1['full_path_client'])
        logger.critical('file2 %s', file2['full_path_client'])
        logger.critical('tmpfile %s', temp_file)
        logger.error(err)
        input(' HALT !!!!')
        return False
    return True


def verify_block(file, blocknum, block_data=None, data_source_file=None):
    if blocknum == 0 and file['pieces_offset'] < 0:
        # logger.debug('Block shared with previous file, cannot verify')
        return False

    if block_data is None:
        # logger.debug('no block given, reading one')
        if data_source_file is None:
            full_path_client = file['full_path_client']
        else:
            # logger.debug('Reading from alternate file')
            full_path_client = data_source_file['full_path_client']
        try:
            with open(full_path_client, 'rb') as fh:
                fh.seek(blocknum*file['piece_size'] + file['pieces_offset'])
                block_data = fh.read(file['piece_size'])
        except Exception as err:
            logger.error('Fail to verify file %s block %s',
                         file['debug'], blocknum)
            logger.error(err)
            return False
    hash_computed = hashlib.sha1(block_data).hexdigest()

    hash_read = file['torrent'].piece_hashes[blocknum + file['pieces_start']]

    status = (hash_read.lower() == hash_computed.lower())
    # logger.debug('file %s block %s valid %s shouldbe %s',
    #              file['debug'], blocknum, status, file['piece_states'][blocknum])
    # print('expected', hash_read, 'computed', hash_computed)
    return status


def recheck_file(file, full_check=False):
    logger.debug('----- RECHECK -----')
  # logger.debug('looking for>%s>%s', file['debug'], file['filename'])
  # logger.debug('offset %s blocksize %s', file['piece_offset'], size_to_dib(file['piece_size']))

    if not os.path.isfile(file['full_path_client']):
      # logger.debug('file to recheck not found')
        return False
    good_blocks = 0
    new_good_blocks = 0
    new_bad_blocks = 0
    bad_blocks = 0
    all_blocks = len(file['piece_states'])
    if full_check:
        for blocknum, status in enumerate(file['piece_states']):
            if verify_block(file, blocknum):
                good_blocks += 1
                if status == 0:
                    new_good_blocks += 1
                    print('O', end='')
                else:
                    print('o', end='')
            else:
                if status == 2:
                    new_bad_blocks += 1
                    print('!', end='')
                else:
                    bad_blocks+=1
                    print('.', end='')
        print()
        print(f'{good_blocks} good {new_good_blocks} NEW good, blocks out of {all_blocks} total')
        print(f'and {new_bad_blocks} that were good are actuall bad')
    else:

        for blocknum, status in enumerate(file['piece_states']):
            if status == 2:
                good_blocks += 1
                print('o', end='')
            else:
                if verify_block(file, blocknum):
                    good_blocks += 1
                    new_good_blocks += 1
                    print('O', end='')
                else:
                    bad_blocks+=1
                    print('.', end='')
        print()
        print(
            f'{good_blocks} good , {new_good_blocks} NEW good blocks out of {all_blocks} total'
            )

    return (good_blocks, new_good_blocks, bad_blocks, new_bad_blocks)


def copy_ranges(target, source, ranges):
  # logger.debug('opening target')
    with open(target['full_path_client'], 'rb+') as fh_tg:
        logger.debug('opening source file')
        with open(source['full_path_client'], 'rb') as fh_src:
            for range_ in ranges:
                start = range_.lower
                end = range_.upper + 1
                fh_src.seek(start)
                fh_tg.seek(start)
                bytes_left = end - start
                while bytes_left > 0:
                    buffersize = min(
                        bytes_left, buffer_size)
                  # logger.debug('copying %s bytes from %s to %s',
                  #  buffersize, source['debug'], target['debug'])
                    data_chunk = fh_src.read(buffersize)
                    fh_tg.write(data_chunk)
                    bytes_left -= buffersize


def copy_ranges_max(target, source, ranges):
  # logger.debug('opening target')
    with open(target['full_path_client'], 'rb+') as fh_tg:
      # logger.debug('opening source file')
        with open(source['full_path_client'], 'rb+') as fh_src:
            for range_ in ranges:
                start = range_.lower
                end = range_.upper + 1
                fh_src.seek(start)
                fh_tg.seek(start)
                src_file_pos = start
                bytes_left = end - start
                while bytes_left > 0:
                    buffersize = min(
                        bytes_left, buffer_size)
                  # logger.debug('copying %s bytes from %s to %s',
                  #  buffersize, source['debug'], target['debug'])
                    data_chunk1 = fh_src.read(buffersize)
                    data_chunk2 = fh_tg.read(buffersize)

                    data_array1 = np.frombuffer(
                        data_chunk1, dtype=np.ubyte, count=-1)
                    data_array2 = np.frombuffer(
                        data_chunk2, dtype=np.ubyte, count=-1)
                    data_array_max = np.fmax(data_array1, data_array2)

                    fh_tg.seek(src_file_pos)
                    fh_tg.write(data_array_max.tobytes())

                    bytes_left -= buffersize
                    src_file_pos += buffersize