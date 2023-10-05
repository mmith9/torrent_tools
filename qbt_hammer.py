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
from autoram.ranges import II, get_block_ranges, estimate_gain_from_repair, shift_ranges, sum_ranges, size_to_dib
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

        if time.time() - t_start > config.getint('behaviour', 'timeout'):
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
            # logger.debug('verify size failed')
            return False

    return merge_multi_ready(files)


def ask_user(question, choices):
    answer = 'none'
    while answer not in choices:
        answer = input(question)
    return answer


def merge_multi_ready(files):
    files_exist = 0
    for file in files:
        if file['file_exists']:
            files_exist += 1
    if files_exist <=1:
        print('phys file in group: {files_exist} in group {files[0]["filename"]}')
        return False

    files.sort(key=lambda x: x['progress'], reverse=True)
    file = files[0]
    if file['progress'] == 1:
        logger.info(
            'There is allready a complete file in group: \n%s', file['filename'])
        return False

    infohash = file['torrent'].hash
    print('Trying ', file['filename'])
    print('copies:')
    for copy in files[1:]:
        print(copy['filename'])

    est_gain, est_left = estimate_gain_from_repair(file, files[1:])
    est_gain_bytes = sum_ranges(est_gain)
    est_left_bytes = sum_ranges(est_left)
    print('estimated gain', size_to_dib(est_gain_bytes))
    print('estimated left', size_to_dib(est_left_bytes))

    if args.auto and est_gain_bytes == 0:
        return False
    elif not args.auto and ask_user('Repair?', ['y', 'n']) == 'n':
        return False

    num_blocks_fixed = 0
    blocks_fixed = []
    for blocknum, status in enumerate(file['piece_states']):
        if status != 2:
            rebuilt = rebuild_block(file, blocknum, files[1:])
            if rebuilt:
                blocks_fixed.append(blocknum)
                num_blocks_fixed += 1
                print('O', end='')
            else:
                print('.', end='')
        else:
            print('o', end='')
    print('\n')
    print('blocks fixed:', num_blocks_fixed)

    end_now = False
    if args.auto:
        if not args.hammer:
            end_now = True

    elif not args.auto and ask_user('hammer file?', ['y', 'n']) == 'n':
        end_now = True

    if end_now:
        if num_blocks_fixed > 0:
            return infohash
        else:
            return False

    num_blocks_hammered = 0
    blocks_hammered = []
    for blocknum, status in enumerate(file['piece_states']):
        if blocknum in blocks_fixed:
            print('O', end='')
            continue
        if status != 2:
            rebuilt = hammer_block(file, blocknum, files[1:])
            if rebuilt:
                blocks_hammered.append(blocknum)
                num_blocks_hammered += 1
                print('T', end='')
            else:
                print('.', end='')
        else:
            print('o', end='')
    print('\n')
    print('blocks hammered:', num_blocks_hammered)
    if num_blocks_fixed + num_blocks_hammered > 0:
        return infohash
    else:
        return False

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
    count = 0
    group_limit = config.getint('behaviour', 'group_limit')
    for _, files in file_dict.items():
        count += 1
        print(f'{count}/{groups_total} ', end='')
        if len(files) > group_limit:
            logger.debug(
                'skipping group of size %s too many files', files[0]['size'])
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

    if config.get('behaviour', 'hammer_matching').lower() != 'true':
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

    need_ranges, block_size = get_block_ranges(source_file, blocknum)

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

    block_data = np.zeros(block_size, dtype=np.ubyte)
    for file in all_files:
        usable_ranges = need_ranges & file['ranges_complete']
        assert len(usable_ranges) <= 1
        if usable_ranges != II.empty():
            data_lower = usable_ranges.lower - need_ranges.lower
            data_upper = usable_ranges.upper - need_ranges.lower + 1
            range_data = read_ranges(file, usable_ranges)

            block_data[data_lower:data_upper] = range_data
            need_ranges = need_ranges - usable_ranges

    is_shared_block = (blocknum == 0 and source_file['first_block_shared']) or \
        (blocknum == len(source_file['piece_states'])
         and source_file['last_block_shared'])

    # logger.debug('block %s , shared? %s', blocknum, is_shared_block)

    if is_shared_block:
        block_fixed = verify_block_shared(
            source_file, blocknum=blocknum, block_data=block_data, source_files=source_files)
        logger.debug('Tried to verify SHARED block, result %s', block_fixed)
    else:
        block_fixed = verify_block(
            source_file, blocknum=blocknum, block_data=block_data)
        # print('verify ', block_fixed)

    if block_fixed:
        # logger.debug('block %s fixed', blocknum)
        return write_block(source_file, blocknum, block_data)

def detect_non_zero_ranges_in_block(data, max_subblock_size):
    # print('`',len(data), end='')
    if not np.any(data):
        return II.empty()

    if len(data) < max_subblock_size:
        end = len(np.trim_zeros(data, 'b'))
        start = len(data) - len(np.trim_zeros(data, 'f'))
        return II.closedopen(start, end)

    half = int(len(data)/2)
    r1 = detect_non_zero_ranges_in_block(data[0:half], max_subblock_size)
    r2 = detect_non_zero_ranges_in_block(data[half:], max_subblock_size)
    r2 = shift_ranges(r2, half)
    return r1 | r2


def hammer_block(source_file, blocknum, source_files):
  # logger.debug('------- block --------- ')
    # logger.debug('blocknum %s', blocknum)
    all_files = []
    all_files.append(source_file)
    all_files.extend(source_files)

    need_ranges, block_size = get_block_ranges(source_file, blocknum)

    block_pool = []
    block_pool.append(np.zeros(block_size, dtype=np.ubyte))
    for file in all_files:
        block = read_ranges(file, need_ranges)
        if block is not False:
            block_pool.append(block)

    check_ranges = [need_ranges]
    # logger.debug(' check ranges %s', len(check_ranges))
    for file in source_files:
        possible_ranges = need_ranges & file['ranges_complete']
        if possible_ranges != II.empty():
            check_ranges.append(possible_ranges)
    # logger.debug(' check ranges %s', len(check_ranges))

    shifted_atomic_ranges = []
    for ranges in check_ranges:
        for atomic in ranges:
            atomic = II.closed(atomic.lower - need_ranges.lower,
                               atomic.upper-need_ranges.lower)
            shifted_atomic_ranges.append(atomic)
    # logger.debug(' shifted atomic ranges %s', len(shifted_atomic_ranges))

    for data_block in block_pool:
        max_subblock_size = int(
            len(data_block) / (2 ^ config.getint('behaviour', 'slicing_depth')))
        ranges = detect_non_zero_ranges_in_block(data_block, max_subblock_size)
        # print(ranges, end=' ')
        for atomic in ranges:
            atomic = II.closed(atomic.lower, atomic.upper)
            shifted_atomic_ranges.append(atomic)
    # logger.debug(' shifted atomic ranges %s', len(shifted_atomic_ranges))

    hammer_ranges = []
    shifted_atomic_ranges = list(set(shifted_atomic_ranges))
    while len(shifted_atomic_ranges) > 0:
        # print('*', len(shifted_atomic_ranges), end='')
        atomic0 = shifted_atomic_ranges.pop()
        no_overlap = True
        for atomic in reversed(shifted_atomic_ranges):
            if atomic0 & atomic != II.empty():
                no_overlap = False
                shifted_atomic_ranges.remove(atomic)
                for fission in [atomic0 - atomic, atomic - atomic0, atomic0 & atomic]:
                    if fission != II.empty():
                        for subatomic in fission:
                            shifted_atomic_ranges.append(
                                II.closed(subatomic.lower, subatomic.upper))
        if no_overlap:
            hammer_ranges.append(atomic0)
    # print('\n')
    hammer_ranges.sort(key=lambda x: x.lower)
    # logger.debug('got %s atomic ranges to work with', len(hammer_ranges))
    # logger.debug('block of %s split into %s',block_size,  len(hammer_ranges))
    # print(hammer_ranges)

    block_matrix = {}
    # logger.debug('hammer ranges %s', hammer_ranges)
    for atomic in hammer_ranges:

        # logger.debug('atomic %s', atomic)
        # logger.debug('block pool is %s', len(block_pool))
        block_matrix[atomic] = []
        for block in block_pool:
            # logger.debug(block)
            # logger.debug('block length %s', len(block))
            new_atomic_block = block[atomic.lower:atomic.upper+1]
            is_dupe = False
            for existing_atomic_block in block_matrix[atomic]:
                if np.array_equal(new_atomic_block, existing_atomic_block):
                    is_dupe = True
                    break
            if not is_dupe:
                block_matrix[atomic].append(new_atomic_block)

    # logger.debug('block map')
    variants = 1
    for atomic in hammer_ranges:
        variants *= len(block_matrix[atomic])
        # print(f'range: {atomic} of {len(block_matrix[atomic])} variants')
    # if variants == 1:
        # logger.debug('only 1 variant,, bailing')
        # return False

  # logger.debug('Possible %s variants to hammer', variants)

    counters = {}
    test_range = II.empty()
    # logger.debug('blocksize %s', block_size)
    hammered_block = np.zeros(block_size, dtype=np.ubyte)
    # logger.debug('hammering block of size %s', len(hammered_block))
    for x in hammer_ranges:
        counters[x] = 0
        test_range = test_range | x
        hammered_block[x.lower:x.upper+1] = block_matrix[x][0]

    # logger.debug('need %s hammer is %s', need_ranges, test_range)

    is_shared_block = (blocknum == 0 and source_file['first_block_shared']) or \
        (blocknum == len(source_file['piece_states'])
         and source_file['last_block_shared'])
  # logger.debug('block %s , shared? %s', blocknum, is_shared_block)

    # check if long 0 patch exists
    # if args.hammer.fail.quick
    for atomic in hammer_ranges:
        bm_a = block_matrix[atomic]
        if len(bm_a) == 1 and len(bm_a[0] > 1000) and not np.any(bm_a[0]):
          # logger.debug('Big unavoidable chain of 0, quick skip')
            # means there is unavoidable chain of 1000 zeros = most likely cant hammer
            return False

    # print('!', end='')
    while True:

        # print('`', end='')
        if is_shared_block:
            block_fixed = verify_block_shared(
                source_file, blocknum=blocknum, block_data=hammered_block, source_files=source_files)
            logger.debug(
                'Tried to verify SHARED block, result %s', block_fixed)
        else:
            block_fixed = verify_block(
                source_file, blocknum=blocknum, block_data=hammered_block)
            # print('verify ', block_fixed)

        # print('`', end='')
        if block_fixed:
            # print('#########################')
            # logger.debug('block %s fixed', blocknum)
            result = write_block(source_file, blocknum, hammered_block)
            # print('#########################')
            return result

        # print('`', end='')
        all_zeroed = True
        for x in hammer_ranges:
            print('.', end='')
            counters[x] += 1
            if counters[x] >= len(block_matrix[x]):
                counters[x] = 0
                hammered_block[x.lower:x.upper +
                               1] = block_matrix[x][counters[x]]
            else:
                hammered_block[x.lower:x.upper +
                               1] = block_matrix[x][counters[x]]
                all_zeroed = False
                break

        # print('`', end='')
        if all_zeroed:
            print()
            break

  # logger.debug('looping complete hammer failed')
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
                logger.debug(
                    'alt file %s has first shared block too', file['debug'])
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
    logger.info('Retrieving torrent info')
    if args.process_all:
        torrents = qbt_client.torrents_info()
    else:
        torrents = qbt_client.torrents_info(filter='resumed')
    # torrents = qbt_client.torrents_info(torrent_hashes=test_hashes)

    logger.info('Got torrents')

    dict_params = {
        'tg_regex': args.tg_regex,
        'filemax': 0,
    }

    logger.info('construct file dict')
    file_dict = construct_file_dict(torrents, dict_params)
    merge_list = find_files_to_merge(file_dict)

    print(f'groups: {len(merge_list)} of ', end='')
    for group in merge_list:
        print(f'{len(group)} ', end='')
    print('files')

    hashes = get_unique_hashes(merge_list)
    print('unique torrents', len(hashes))
    print(hashes)
    print('Merge start')

    hashes_to_recheck = []
    for group in merge_list:
        logger.debug('merging group of %s', len(group))
        result = merge_multi(group)
        if result:
            hashes_to_recheck.append(result)

    print('resuming torrents')
    qbt_client.torrents_resume(torrent_hashes=hashes_to_recheck)
    print('forcing rechecks')
    for infohash in hashes_to_recheck:
        print(infohash)
    qbt_client.torrents_recheck(torrent_hashes=hashes_to_recheck)


if __name__ == "__main__":
    from argparse import ArgumentParser
    parser = ArgumentParser(
        description='hammer till they finish')

    parser.add_argument('-all', dest='process_all', default=False, action='store_true',
                        help='Inject into paused files too, default false')

    parser.add_argument('-hammer', default=False, action='store_true',
                        help='Try hard to rebuild')

    parser.add_argument('-hardmerge', default=False, action='store_true',
                        help='Point both torrents to 3rd (possible merged) file')

    parser.add_argument('-verify', default=False, action='store_true',
                        help='Check if any new blocks appeared')

    parser.add_argument('-debug', dest='debug', action='store_true')

    parser.add_argument('-tg_regex', dest='tg_regex', default='', type=str)

    parser.add_argument('-auto', action='store_true')

    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    time_start = time.time()
    main()
    time_end = time.time()
    total_time = time_end - time_start
    print("\nExecution time: " + str(total_time))
