#!/usr/bin/env python -u

import configparser
import logging
import logging.config
import os
import shutil
import sys
import time
from typing import List, Tuple

import numpy as np

from autoram.files_on_disk import (get_client_path_to_backup_dir, get_full_client_path_for_torrent_file, read_ranges, scan_tree,
                                   verify_and_fix_physical_file, verify_block, write_block)
from autoram.klasses import FileOfSize
from autoram.qbt_api import connect_qbt
from autoram.ranges import (II, estimate_gain_from_repair, get_block_ranges,
                            shift_ranges, size_to_dib, sum_ranges)
from autoram.test_hashes import test_hashes
from autoram.tr_payload import (construct_file_dict, filterout_nometa_and_completeds, get_sizes_dict, is_file_unique_to_group,
                                match_same_size_files_multi)

logging.config.fileConfig('logging.conf')
logger = logging.getLogger(__name__)

config = configparser.ConfigParser(allow_no_value=True, delimiters='=')
config.read('autoram.ini')


def merge_multi(files):
    # logger.debug('merge multi with %s files', len(files))
    hashes = []
    for file in files:
        hashes.append(file['torrent'].hash)

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
        if file['file_exists']:
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
    existing_files = []
    empty_files = []
    unique_files = []
    hashes_to_recheck = set()

    for file in files:
        if file['progress'] == 1:
            logger.info(
                'There is allready a complete file in group: \n%s', file['filename'])
            # return False
        if not is_file_unique_to_group(file, unique_files):
            continue
        unique_files.append(file)
        if file['file_exists']:
            existing_files.append(file)
        else:
            empty_files.append(file)

    if len(existing_files) <1:
        print('Not enough existing files to do anything')
        return False

    existing_files.sort(key=lambda x: x['progress'], reverse=True)

    if args.crossmerge:
        files0 = existing_files.copy()
    else:
        files0 = existing_files[:1]

    for file0 in files0:
        other_files = existing_files.copy()
        other_files.remove(file0)

        print(f"Parent {size_to_dib(file0['size'])} \n{file0['full_path_client']}")
        print('copies :')

        for file in unique_files:
            if file == file0:
                continue
            if file in existing_files:
                print('(EXISTS)', file['full_path_client'])
            else:
                print('(NOFILE)', file['filename'])

        if len(other_files) == 0:
            continue

        blocks_fixed = loop_rebuild_block(file0, other_files)

        logger.debug('hammer decision point')
        if len(blocks_fixed) > 0 :
            hashes_to_recheck.add(file0['hash'])

        end_now = False
        if args.auto:
            if not args.hammer and not args.hardmerge:
                end_now = True
        elif not args.auto and ask_user('hammer file?', ['y', 'n']) == 'n':
            end_now = True

        if end_now:
            continue
        
        logger.debug('entering hammer subroutine')
        blocks_hammered = loop_hammer_block(
            file0, other_files, blocks_fixed)
        logger.debug('hammering subroutine exiting')
        if len(blocks_hammered) > 0:
            hashes_to_recheck.add(file0['hash'])

    # exclusive with cross merge
    if not args.crossmerge:
        end_now = False
        if args.auto:
            if not args.hardmerge:
                end_now = True
        elif not args.auto and ask_user('hardmerge file?', ['y', 'n']) == 'n':
            end_now = True
        if end_now:
            return list(hashes_to_recheck)

        result = hard_merge(file0, unique_files)
        if result:
            result.append(file0['hash'])
            return result        

    return list(hashes_to_recheck)


def find_files_to_merge(file_dict):
    merge_list = []
    groups_total = len(file_dict)
    count = 0
    group_limit = config.getint('behaviour', 'group_limit')
    logger.info('found %s size groups', groups_total)
    for _, files in file_dict.items():
        count += 1
        print(f'{count}', end='   \r')
        if len(files) > group_limit:
            print()
            logger.debug(
                'skipping group of size %s too many files', files[0]['size'])
            continue
        if len(files) <= 1:
            # logger.debug('skipping lone file in group of size %s ', files[0]['size'])
            continue

        groups_to_merge = match_same_size_files_multi(files)
        merge_list.extend(groups_to_merge)

    filtered_merge_list = []
    for group in merge_list:
        new_group = []
        for file in group:
            if is_file_unique_to_group(file, new_group):
                new_group.append(file)
        if len(new_group) > 1:
            filtered_merge_list.append(new_group)
    print()
    logger.info('Got %s groups to work with', len(filtered_merge_list))
    return filtered_merge_list


def get_unique_hashes(merge_list):
    hashes = set()
    for group in merge_list:
        for file in group:
            hashes.add(file['torrent'].hash)
    return list(hashes)


def loop_rebuild_block(file0, files):

    blocks_fixed = []
    est_gain, est_left = estimate_gain_from_repair(file0, files)
    est_gain_bytes = sum_ranges(est_gain)
    est_left_bytes = sum_ranges(est_left)
    print('estimated gain', size_to_dib(est_gain_bytes))
    print('estimated left', size_to_dib(est_left_bytes))

    if args.auto and est_gain_bytes == 0:
        return blocks_fixed
    elif not args.auto and ask_user('Repair?', ['y', 'n']) == 'n':
        return blocks_fixed

    num_blocks_fixed = 0

    for blocknum, status in enumerate(file0['piece_states']):
        if status != 2:
            rebuilt = rebuild_block(file0, blocknum, files)
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
    return blocks_fixed


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
        # logger.debug('file %s, need %s, usable %s, rebuild %s',file['debug']\
        #  , need_ranges, usable_ranges, rebuild_ranges)
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
        if len(usable_ranges) > 1:
            logger.error('assertion error for usable ranges, should be monoblock')
            logger.error('file %s', file['full_path_client'])
            logger.error('need ranges %s', need_ranges)
            logger.error('usable ranges %s', usable_ranges)
            input('Enter to proceed...')
            continue
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


def loop_hammer_block(file0, files, blocks_fixed):
    num_blocks_hammered = 0
    blocks_hammered = []
    for blocknum, status in enumerate(file0['piece_states']):
        logger.debug('considering block %s', blocknum)
        if blocknum in blocks_fixed:
            print('O', end='')
            continue
        if status != 2:
            logger.debug('hammering block %s', blocknum)
            rebuilt = hammer_block(file0, blocknum, files)
            logger.debug('hammering done')
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
    return blocks_hammered

def print_debug(text:str, end:str='\n')->None:
    if logger.getEffectiveLevel()<=logging.DEBUG:
        print(text, end=end)

def input_debug():
    if logger.getEffectiveLevel()<=logging.DEBUG:
        input('Enter')

def hammer_block(source_file, blocknum, source_files):
    logger.debug('------- block --------- ')
    logger.debug('blocknum %s', blocknum)
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
    logger.debug('parent file check ranges %s', len(check_ranges))
    copies_ranges = []
    for file in source_files:
        possible_ranges = need_ranges & file['ranges_complete']
        if possible_ranges != II.empty():
            copies_ranges.append(possible_ranges)
    logger.debug('copies ranges %s', len(check_ranges))
    check_ranges.extend(copies_ranges)
    logger.debug('combined ranges %s', len(check_ranges))

    shifted_atomic_ranges = []
    for ranges in check_ranges:
        for atomic in ranges:
            atomic_shifted = II.closed(atomic.lower - need_ranges.lower,
                               atomic.upper-need_ranges.lower)
            shifted_atomic_ranges.append(atomic_shifted)
    del check_ranges
    logger.debug('combined shifted atomic ranges %s', len(shifted_atomic_ranges))

    print_debug('Detecting zero ranges in possible blocks', end=' ')
    for data_block in block_pool:
        max_subblock_size = int(
            len(data_block) / (2 ^ config.getint('behaviour', 'slicing_depth')))
        zero_ranges = detect_non_zero_ranges_in_block(data_block, max_subblock_size)
        print_debug(zero_ranges, end=' ')
        for atomic in zero_ranges:
            atomic_shifted = II.closed(atomic.lower, atomic.upper)
            shifted_atomic_ranges.append(atomic_shifted)
    print_debug('')
    logger.debug('Total shifted atomic ranges %s', len(shifted_atomic_ranges))

    hammer_ranges = []
    shifted_atomic_ranges = list(set(shifted_atomic_ranges))
    logger.debug('Total deduped shifted atomic ranges %s', len(shifted_atomic_ranges))

    while len(shifted_atomic_ranges) > 0:
        print_debug(f'*{len(shifted_atomic_ranges)} ', end=' ')
        atomic0 = shifted_atomic_ranges.pop()
        no_overlap = True
        for atomic in reversed(shifted_atomic_ranges):
            if atomic0 == atomic:
                shifted_atomic_ranges.remove(atomic)
                continue                
            if atomic0 & atomic != II.empty():
                print_debug('overlap of ', end ='')
                print_debug(atomic0, end=' ')
                print_debug(atomic, end=' ')
                no_overlap = False
                shifted_atomic_ranges.remove(atomic)
                print_debug('fission to: ', end ='')
                for fission in [atomic0 - atomic, atomic - atomic0, atomic0 & atomic]:
                    if fission != II.empty():
                        for subatomic in fission:
                            print_debug(subatomic, end =' ')
                            shifted_atomic_ranges.append(
                                II.closed(subatomic.lower, subatomic.upper))
                print_debug(':end')
                print_debug(shifted_atomic_ranges)
                input_debug()
                break
        if no_overlap:
            hammer_ranges.append(atomic0)
    print_debug('\n')
    hammer_ranges.sort(key=lambda x: x.lower)
    logger.debug('got %s atomic ranges to work with', len(hammer_ranges))
    logger.debug('block of %s split into %s',block_size,  len(hammer_ranges))
    print_debug(hammer_ranges)

    block_matrix = {}
    logger.debug('hammer ranges %s', hammer_ranges)
    for atomic in hammer_ranges:

        logger.debug('atomic %s', atomic)
        logger.debug('block pool is %s', len(block_pool))
        block_matrix[atomic] = []
        for block in block_pool:
            logger.debug(block)
            logger.debug('block length %s', len(block))
            new_atomic_block = block[atomic.lower:atomic.upper+1]
            is_dupe = False
            for existing_atomic_block in block_matrix[atomic]:
                if np.array_equal(new_atomic_block, existing_atomic_block):
                    is_dupe = True
                    break
            if not is_dupe:
                block_matrix[atomic].append(new_atomic_block)

    logger.debug('block map')
    variants = 1
    for atomic in hammer_ranges:
        variants *= len(block_matrix[atomic])
        print_debug(f'range: {atomic} of {len(block_matrix[atomic])} variants')
    if variants == 1:
        logger.debug('only 1 variant,, bailing')
        return False

    logger.debug('Possible %s variants to hammer', variants)

    counters = {}
    test_range = II.empty()
    logger.debug('blocksize %s', block_size)
    hammered_block = np.zeros(block_size, dtype=np.ubyte)
    logger.debug('hammering block of size %s', len(hammered_block))
    for x in hammer_ranges:
        counters[x] = 0
        test_range = test_range | x
        hammered_block[x.lower:x.upper+1] = block_matrix[x][0]

    logger.debug('need %s hammer is %s', need_ranges, test_range)

    is_shared_block = (blocknum == 0 and source_file['first_block_shared']) or \
        (blocknum == len(source_file['piece_states'])
         and source_file['last_block_shared'])
    logger.debug('block %s , shared? %s', blocknum, is_shared_block)

    # check if long 0 patch exists
    # if args.hammer.fail.quick
    for atomic in hammer_ranges:
        bm_a = block_matrix[atomic]
        if len(bm_a) == 1 and len(bm_a[0] > 1000) and not np.any(bm_a[0]):
            logger.debug('Big unavoidable chain of 0, quick skip')
        #    means there is unavoidable chain of 1000 zeros = most likely cant hammer
            return False

    
    print_debug('!', end='')
    while True:
        print_debug('`', end='')
        if is_shared_block:
            block_fixed = verify_block_shared(
                source_file, blocknum=blocknum, 
                block_data=hammered_block, source_files=source_files)
            logger.debug(
                'Tried to verify SHARED block, result %s', block_fixed)
        else:
            block_fixed = verify_block(
                source_file, blocknum=blocknum, block_data=hammered_block)
            print_debug(f'verify {block_fixed}')

        print_debug('`', end='')
        if block_fixed:
            print_debug('#########################')
            logger.debug('block %s fixed', blocknum)
            result = write_block(source_file, blocknum, hammered_block)
            print_debug('#########################')
            return result

        print_debug('`', end='')
        all_zeroed = True
        for x in hammer_ranges:
            print_debug('.', end='')
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

        print_debug('`', end='')
        if all_zeroed:
            print_debug()
            break

    logger.debug('looping complete hammer failed')
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


def hard_merge(file0, all_files):
    time_now = int(time.time())
    logger.debug('hard merging %s files to %s',
                 len(all_files)-1, file0['filename'])

    hashes_to_recheck = []
    # point torrents to parent and stash obsolete files in autoram dir
    for file in all_files:
        if file == file0:
            continue

        if file['file_exists']:
            backup_dir = get_client_path_to_backup_dir(file)
            logger.debug('moving %s to', file['filename'])
           
            new_path_client = os.path.join(backup_dir, file['hash'])
            # new_path_client = os.path.join(new_path_client, file['filename'])

            #dir_to_make, _ = os.path.split(new_path_client)
            os.makedirs(new_path_client, exist_ok=True)
            shutil.move(file['full_path_client'], new_path_client)
            logger.debug('file moved')

            with open(
                os.path.join(backup_dir,f'log_{time_now}.txt'), 'a', encoding='utf-8') as fh:

                fh.writelines(f'''
---------
epoch: {int(time.time())}
hash1: {file['hash']}
torrent1: {file['torrent'].name}
file1: {file['filename']}
old path: {file['full_path_client']}
new path: {new_path_client}
dest: {file0['filename']}

        ''')

        logger.info('Renaming file in qbittorrent')
        args.qbt_client.torrents_rename_file(
            torrent_hash=file['hash'], file_id=file['id'],
            old_path=file['path_server'],
            new_path=file0['path_server']
        )

        args.qbt_client.torrents_set_category(category=file0['category'], torrent_hashes=file['hash']) 

        args.qbt_client.torrents_add_tags(
            torrent_hashes=file['hash'], tags=['_ram_clone', '_cmp'])
        hashes_to_recheck.append(file['hash'])

    args.qbt_client.torrents_add_tags(
        torrent_hashes=file0['hash'], tags=['_ram_parent', '_cmp'])
    hashes_to_recheck.append(file0['hash'])

    return hashes_to_recheck



def main():
    logger.info('Connecting to server')
    qbt_client = connect_qbt()
    args.qbt_client = qbt_client
    logger.info('Retrieving torrent info')
    if args.process_all:
        torrents = qbt_client.torrents_info()
    else:
        torrents = qbt_client.torrents_info(filter='resumed')

    torrents = filterout_nometa_and_completeds(torrents)

    dict_of_sizes, filtered_hashes = get_sizes_dict(torrents, args.dirs)
    print(f'torrents {len(torrents)} filtered {len(filtered_hashes)}')
    if len(filtered_hashes) == 0:
        print('quitting')
        sys.exit(0)
    del torrents
    torrents = qbt_client.torrents_info(torrent_hashes=filtered_hashes)
    print(f'again torrents {len(torrents)}')
    logger.info('Got torrents')

    dict_params = {
        'tg_regex': args.tg_regex,
        'filemax': 0,
    }

    logger.info('construct file dict')
    file_dict = construct_file_dict(torrents, dict_params, args.disable_regex)
    merge_list = find_files_to_merge(file_dict)

    print(f'groups: {len(merge_list)} of ', end='')
    for group in merge_list:
        print(f'{len(group)} ', end='')
    print('\nfiles')

    hashes = get_unique_hashes(merge_list)
    print('unique torrents', len(hashes))
    print(hashes)
    print('Merge start')

    hashes_to_recheck = []
    count  = 0
    count_total = len(merge_list)
    for group in merge_list:
        count+=1
        if len(group) <= 1:
            continue

        print(f'\nGroup {count} of {count_total} ')

        logger.debug('merging group of %s', len(group))
        result = merge_multi(group)
        if result:
            hashes_to_recheck.extend(result)

    answer = 'y' if args.auto else ''
    while answer not in ['y', 'n']:
        answer = input('resume torrents? <y/n>').lower()
    if answer == 'y':
        qbt_client.torrents_resume(torrent_hashes=hashes_to_recheck)

    answer = 'y' if args.auto else ''
    while answer not in ['y', 'n']:
        answer = input('force rechecks? <y/n>').lower()
    if answer == 'y':
        qbt_client.torrents_recheck(torrent_hashes=hashes_to_recheck)

    print('Altered torrents')
    for infohash in set(hashes_to_recheck):
        print(infohash)
    


if __name__ == "__main__":
    from argparse import ArgumentParser
    parser = ArgumentParser(
        description='hammer till they finish')

    parser.add_argument('dirs', type=str, nargs='*',
                        help='directories to scan, if "all", read them from config')

    parser.add_argument('-all', dest='process_all', default=False, action='store_true',
                        help='Process all torrent, default - only resumed')

    parser.add_argument('-x', '--crossmerge', dest='crossmerge', default=False, action='store_true',
        help='Repair each file in each group instad of just one, exclusive with hardmerge')

    parser.add_argument('-hm','--hammer', dest='hammer', default=False, action='store_true',
                        help='Try harder to rebuild')

    parser.add_argument('-hr', '--hardmerge', dest='hardmerge', default=False, action='store_true',
                        help='Repair the most complete file and point other torrents to that file')

    parser.add_argument('-v','--verify', default=False, action='store_true',
                        help='Check if any new blocks appeared')

    parser.add_argument('-debug', dest='debug', action='store_true', default=False)

    parser.add_argument('-tg_regex', dest='tg_regex', default='', type=str)

    parser.add_argument('-disable_regex', action='store_true', default=False, help='Disable exclude regexes')

    parser.add_argument('-auto', action='store_true')

    args = parser.parse_args()

    #print(__name__)
    #logger.debug('init check')

    if args.debug:
        #print(logger.getEffectiveLevel())
        print('turning debug on')
        logger.setLevel(logging.DEBUG)
    logger.debug('.')
    logger.info('.')
    logger.warning('.')
    logger.error('.')
    logger.critical('.')
    print('debug level is', logger.getEffectiveLevel())
    print_debug('print on debug passed')
        

    if args.hardmerge and args.crossmerge:
        print('hardmerge and crossmerge are mutually exclusive')
    else:
        time_start = time.time()
        main()
        time_end = time.time()
        total_time = time_end - time_start
        print("\nExecution time: " + str(total_time))
