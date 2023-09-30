#!/usr/bin/env python -u

import configparser
import hashlib
import logging
import logging.config
import os
import time

import numpy as np


from autoram.qbt_api import connect_qbt
from autoram.tr_payload import construct_file_dict
from autoram.ranges import II, get_block_ranges, estimate_gain_from_repair, sum_ranges, size_to_dib
from autoram.test_hashes import test_hashes
from autoram.files_on_disk import verify_and_fix_physical_file
from autoram.files_on_disk import read_block, read_ranges, write_block,\
    verify_block, recheck_file, swap_files_inplace

logging.config.fileConfig('logging.conf')
logger = logging.getLogger(__name__)

config = configparser.ConfigParser()
config.read('autoram.ini')

def merge_multi(files):
    # logger.debug('merge multi with %s files', len(files))
    hashes = []
    for file in files:
        hashes.append(file['torrent'].hash)
        if file['file'].size != files[0]['file'].size:
            logger.error('final file sizes mismatch %s %s',
                         files[0]['file'].size, file['file'].size)
            return False

    all_paused = False
    t_start = time.time()
    while not all_paused:

        if time.time() - t_start > config.getint('behaviour','timeout'):
            logger.error('torrents not paused timeout')
            print('Torrents not paused timeout')
            answer = 'null'
            while answer.lower() not in ['r', 'a', 'i']:
                answer = input(
                    '(r)etry pausing, (i)gnore pausing, (s)kip').lower()

            if answer == 'r':
                t_start = time.time()
                continue
            if answer == 's':
                return False
            if answer == 'i':
                break

        torrents = args.qbt_client.torrents_info(hashes=hashes)
        all_paused = True
        for trr in torrents:
            all_paused = all_paused and trr['state'].lower(
            ).startswith('paused')
        if not all_paused:
            args.qbt_client.torrents_pause(hashes=hashes)
            time.sleep(5)

    for file in files:
        if not verify_and_fix_physical_file(file):
            # logger.debug('verify failed')
            return False
   
    quick_fix_files(files)

def quick_fix_files(files):
    files.sort(key= lambda x: x['progress'], reverse = True)
    file = files[0]
    if file['progress'] == 1:
        logger.info('There is allready a complete file in group: \n%s', file['filename'])
        return False

    print('Trying ', file['filename'])
    print('copies:')
    for copy in files[1:]:
        print(copy['filename'])
    #print()
    #print('need ranges', file['ranges_needed'])
    est_gain, est_left =  estimate_gain_from_repair(file, files[1:])
    # print('estimated gain', est_gain)
    # print('estimated gaps left', est_left)
    # print()

    print('estimated gain', size_to_dib(sum_ranges(est_gain)))
    print('estimated left',size_to_dib(sum_ranges(est_left)))

    print('repair?')
    answer = 'x'
    while answer not in ['y','n']:
        answer = input()
    
    if answer == 'n':
        return

    blocks_fixed = 0
    for blocknum, status in enumerate(file['piece_states']):

        if status != 2:
            rebuilt = rebuild_block(file, blocknum, files[1:])
            if rebuilt:
                blocks_fixed +=1
                print('O', end='')
            else:
                print('.', end='')
        else:
            print('o', end='')
    print('\n')
    print('blocks fixed:', blocks_fixed)

    answer = 'x'
    while answer not in ['y','n']:
        answer = input('Recheck file?')
    
    if answer == 'n':
        return
    recheck_file(file, full_check=True)

    answer = 'x'
    while answer not in ['y','n']:
        answer = input('Force qbittorrent recheck?')
    
    if answer == 'n':
        return
    args.qbt_client.recheck(torrent_hashes = file['torrent'].hash)





def find_blocks_in_other_file(file1, file2):
    # logger.debug('looking for >%s>%s', file1['debug'], file1['filename'])
    # logger.debug('offset %s blocksize %s', file1['file_offset'], size_to_dib(file1['piece_size']))
    # logger.debug('in         >%s>%s', file2['debug'], file2['filename'])
    # logger.debug('offset %s blocksize %s', file2['file_offset'], size_to_dib(file2['piece_size']))

    if not os.path.isfile(file2['full_path_client']):
      # logger.debug('file2 not found')
        return False

    ranges = file2['ranges_complete']

    # logger.debug('got %s ranges', len(ranges))
    if not ranges:
        # logger.debug('ranges empty')
        return False

    piece_size = file1['piece_size']
    file_offset = file1['file_offset']
    pieces_offset = -(file_offset % piece_size)

    pieces_start = file1['pieces_start']
    torrent_hashes = file1['torrent'].piece_hashes

    blocknum = 0
    if pieces_offset < 0:
        blocknum = 1

    blocks_found = 0
    tries = 0
    max_tries = 10
    while (blocknum+1)*piece_size + pieces_offset < file1['size']:
        if tries >= max_tries:
          # logger.debug('Failed %s times, skipping', max_tries)
            return False

        byte_start = blocknum*piece_size + pieces_offset
        byte_end = (blocknum+1)*piece_size + pieces_offset

        block_range = II.closedopen(byte_start, byte_end)
        if block_range not in ranges:
            blocknum += 1
            continue

        hash1 = torrent_hashes[blocknum + pieces_start]
        # logger.debug('%s hash read %s', hash1, blocknum + pieces_start)

        try:
            with open(file2['full_path_client'], 'rb') as fh:
                fh.seek(byte_start)
                piece_data = fh.read(piece_size)
                hash2 = hashlib.sha1(piece_data).hexdigest()
            # logger.debug('%s computed: %s', hash2, blocknum)
        except Exception as err:
            logger.error(err)
            tries += 1
            time.sleep(5)
            continue

        blocknum += 1
        if hash1.lower() == hash2.lower():
            blocks_found += 1
        else:
            tries += 1
        if blocks_found >= 3:
            return True
    return False

def find_files_to_merge(file_dict):
    merge_list = []
    groups_total = len(file_dict)
    count =0
    group_limit = config.getint('behaviour','group_limit')
    for _, files in file_dict.items():
        count+=1
        print(f'{count}/{groups_total }', end ='')
        if len(files) > group_limit:
            logger.debug('skipping group of size %s too many files', files[0]['size'])
            continue
        if len(files) <= 1:
            # logger.debug('skipping lone file in group of size %s ', files[0]['size'])
            continue

        groups_to_merge = match_same_size_files_multi(files)
        merge_list.extend(groups_to_merge)
    
    return merge_list


def file_belongs_to_group(file0, group):
    for file in group:
        if find_blocks_in_other_file(file0, file):
            return True
        if find_blocks_in_other_file(file, file0):
            return True
    return False


def match_same_size_files_multi(files_of_same_size):
    files = files_of_same_size
    logger.debug('matching %s files of size %s', len(files), files[0]['size'])
    files.sort(key=lambda x: x['progress'])
    size = files[0]['size']
    groups = []

    while len(files) >= 1:
        file = files.pop()
        for group in groups:
            if file_belongs_to_group(file, group):
                group.append(file)
                file = None
                break
        if file:
            groups.append([file])

    if config.get('behaviour','hammer_matching').lower() != 'true':
        return groups

    logger.debug('trying to match harder')
    # try again, first recoup unassigned files
    assert files == []
    for group in reversed(groups):
        if len(group) == 1:
            files.append(group.pop())
            groups.remove(group)

    files.sort(key=lambda x: x['piece_size'])
    while len(files) >= 1:
        file = files.pop()
        for group in groups:
            if file_belongs_to_group(file, group):
                group.append(file)
                break

    logger.debug('grouping of %s done, groups found %s', size, len(groups))
    return groups


def get_unique_hashes(merge_list):
    hashes = set()
    for group in merge_list:
        for file in group:
            hashes.add(file['torrent'].hash)
    return list(hashes)



def rebuild_block(source_file, blocknum, source_files):
    all_files = []
    all_files.append(source_file)
    all_files.extend(source_files)

    need_ranges, _ = get_block_ranges(source_file, blocknum)

    rebuild_ranges = II.empty()
    #logger.debug('repairing block %s in %s', blocknum, source_file['debug'])
    for file in all_files:
        # print('+++++')
        # print('file', file['debug'])
        # print('file ', file['filename'])
        # print(file['ranges_complete'])
        usable_ranges = need_ranges & file['ranges_complete']
        rebuild_ranges = rebuild_ranges | usable_ranges
        # logger.debug('file %s, need %s, usable %s, rebuild %s',file['debug'] , need_ranges, usable_ranges, rebuild_ranges)
        # if blocknum !=0 and file!=source_file:
        #     xx = verify_block(source_file, blocknum, data_source_file=file)
        #     print(file['debug'],xx)

    #logger.debug('block: %s, rebuild: %s', need_ranges, rebuild_ranges)

    if need_ranges != rebuild_ranges:
        #logger.debug('Cant rebuild block, no pieces in other files')
        return False

    block_data = np.zeros(source_file['piece_size'], dtype=np.ubyte)
    for file in all_files:
        usable_ranges = need_ranges & file['ranges_complete']
        assert len(usable_ranges) <= 1
        if usable_ranges != II.empty():
            data_lower = usable_ranges.lower - need_ranges.lower
            data_upper = usable_ranges.upper - need_ranges.lower +1
            range_data = read_ranges(file, usable_ranges)

            # print('!!!!!')
            # print(data_lower, data_upper, len(range_data), len(block_data))

            block_data[data_lower:data_upper] = range_data


            need_ranges = need_ranges - usable_ranges

    is_shared_block = (blocknum == 0 and source_file['first_block_shared']) or \
        (blocknum == len(source_file['piece_states'])
         and source_file['last_block_shared'])

    # logger.debug('block %s , shared? %s', blocknum, is_shared_block)

    if is_shared_block:
        block_fixed = verify_block_shared(
            source_file, blocknum=blocknum, block_data=block_data, source_files=source_files)
    else:
        block_fixed = verify_block(
            source_file, blocknum=blocknum, block_data=block_data)
        # print('verify ', block_fixed)

    if block_fixed:
        # logger.debug('block %s fixed', blocknum)
        return write_block(source_file, blocknum, block_data)
        


#def hammer_block(source_file, blocknum, source_files):
    # hammer time
    # possible_subs = {}
    # counters = {}
    # for ranges in need_ranges:
    #     possible_subs[ranges] = []
    #     counters[ranges] = 0
    #     for file in all_files:
    #         data = read_ranges(file, ranges)
    #         possible_subs[ranges].append(data)

    # cnt_max = len(counters)

    # while True:
    #     for ranges in need_ranges:
    #         block_data[ranges.lower:ranges.upper] = possible_subs[ranges][counters[ranges]]

    #     if is_shared_block:
    #         block_fixed = verify_block_shared(
    #             srf, blocknum=blocknum, block_data=block_data, source_files=source_files)
    #     else:
    #         block_fixed = verify_block(
    #             srf, blocknum=blocknum, block_data=block_data)

    #     if block_fixed:
    #         logger.debug('block %s fixed', blocknum)
    #         write_block(srf, blocknum, block_data)
    #         return True

    #     for ranges in need_ranges:
    #         counters[ranges] += 1
    #         if counters[ranges] >= cnt_max:
    #             counters[ranges] = 0
    #         else:
    #             break

    #     counter_sum = 0
    #     for ranges in need_ranges:
    #         counter_sum += counters[ranges]
    #     if counter_sum == 0:
    #         break

    return False


def verify_block_shared(srf, blocknum, block_data, source_files):
    logger.debug('alternate verify')
    if not source_files:
        logger.debug('no alternate sources')
        return False

    if blocknum == 0:
        _, srf_first_block_size = get_block_ranges(srf, 0)

        for file in source_files:
            if file['first_block_shared']:
                logger.debug('alt file %s has first shared block too', file['debug'])
                continue

            __, file_first_block_size = get_block_ranges(file, 0)
            if file_first_block_size < srf_first_block_size + srf['pieces_offset']:
                logger.debug('alt file %s got too small blocks ')
                continue

            if not verify_block(file, 0, block_data):
                logger.debug('hash failed')
                continue

            logger.debug('alternate verify of block 0 success')
            return True

    if blocknum == (srf['pieces_end'] - srf['pieces_start']):
        __, srf_last_block_size = get_block_ranges(
            srf, srf['pieces_end'] - srf['pieces_start'])

        for file in source_files:

            if not file['is_last_file_in_torrent']:
                continue

            file_last_block_num = file['pieces_end'] - file['pieces_start']
            file_last_block_size = get_block_ranges(file, file_last_block_num)
            if file_last_block_size < srf_last_block_size + srf['pieces_offset']:
                continue

            if not verify_block(file, file_last_block_num):
                continue

            logger.debug('alternate verify of last block success')
            return True

    return False


def test_(file):
    print('testing ', file['debug'], file['pieces_offset'])
    for num, status in enumerate(file['pieces_stats']):
        print(status, end='')
        print(verify_block(file, num), end=' ')
    print()


def main():

    logger.info('Connecting to server')
    qbt_client = connect_qbt()
    args.qbt_client = qbt_client
    logger.info('Retrieving torrent info - all files')

    torrents = qbt_client.torrents_info(filter = 'resumed') #hashes=test_hashes)

    logger.info('Got torrents')
    logger.info('construct file dict')
    file_dict = construct_file_dict(torrents, filemax=0)
    merge_list = find_files_to_merge(file_dict)

    
    print('groups: ', len(merge_list))
    # print(merge_list)
    hashes = get_unique_hashes(merge_list)
    print('unique torrents', len(hashes))
    print(hashes)
    #decision = input('Enter to start merging')
    # print('pausing torrents')
    # qbt_client.torrents_pause(hashes)

    print('Merge start')

    for group in merge_list:
        logger.debug('merging group of %s', len(group))
        merge_multi(group)
    # print('resuming torrents')
    # qbt_client.torrents_resume(hashes)
    # print('forcing rechecks')
    # qbt_client.torrents_recheck(hashes)

    # time.sleep(10)


if __name__ == "__main__":
    from argparse import ArgumentParser
    parser = ArgumentParser(
        description='delete active torrents automagically if other copy is completed.')

    parser.add_argument('-all', dest='process_all', default=False, action='store_true',
                        help='Inject into paused files too, default false')

    parser.add_argument('-hammer', default=False, action='store_true',
                        help='Try hard to rebuild')

    parser.add_argument('-hardmerge', default=False, action='store_true',
                        help='Point both torrents to 3rd (possible merged) file')

    parser.add_argument('-verify', default=False, action='store_true',
                        help='Check if any new blocks appeared')

    parser.add_argument('-debug', dest='debug', action='store_true')
    parser.add_argument('-yy', dest='auto_yes',
                        action='store_true', help='auto yes all')
    parser.add_argument('-dummy', dest='allow_dummies', default=False,
                        action='store_true', help='allow creation of empty files')

    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    time_start = time.time()
    main()
    time_end = time.time()
    total_time = time_end - time_start
    print("\nExecution time: " + str(total_time))
