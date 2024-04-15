#!/usr/bin/env python -u
import configparser
import logging
import logging.config
import os
import re
import shutil
import sys
import time

import numpy as np

from autoram.files_on_disk import get_full_client_path_for_torrent_file, recheck_file_full
from autoram.qbt_api import connect_qbt
from autoram.ranges import II
from autoram.tr_payload import filter_no_meta, filterout_nometa_and_completeds, find_blocks_in_other_file
from qbt_hammer import get_sizes_dict, rebuild_block

logging.config.fileConfig('logging.conf')
logger = logging.getLogger(__name__)

config = configparser.ConfigParser(allow_no_value=True, delimiters='=')
config.read('autoram.ini')


def construct_file_dict(torrents, dict_params):
    
    torrents = filter_no_meta(torrents)
    file_dict_raw = {}
    logger.info('Processing %s torrents', len(torrents))
    logger.info('Building sizes dictionary')
    count_files = 0

    reg_exclude = '^alwaysfalse$' if args.disable_regex else config.get('behaviour', 'nono_regex')
    filemax = args.file_max if args.file_max else dict_params['filemax']
    min_file_size = args.min_size if args.min_size else config.getint('behaviour', 'min_file_size')
    min_file_size *= 1024*1024

    count_trrs = len(torrents)
    count=0
    count_all_files=0    

    for trr in torrents:
        count_files = 0
        count+=1
        file_offset = 0

        if filemax and count_all_files >= filemax:
            logger.debug('filemax of %s hit', filemax)
            break

        for file in trr.files:
            count_files+=1
            count_all_files += 1
            size = file.size

            skip = (file.priority == 0)
            skip = skip or (size < min_file_size)
            skip = skip or (re.search(reg_exclude, file.name, flags=re.IGNORECASE))
            if skip:
                file_offset += size
                continue

            print(f'torrent {count} of {count_trrs} and {count_files} files', end='\r')
            insert = (trr, file, file_offset)
            if size not in file_dict_raw:
                file_dict_raw[size] = []

            file_dict_raw[size].append(insert)
            file_offset += size
    print()
    return file_dict_raw


def construct_file_dict_raw_part2(file_dict_raw):
    logger.info('Grouping by size, %s sizes', len(file_dict_raw))
    file_dict = {}

    logger.debug('Extracting full info about torrents to check')
    for size, group in file_dict_raw.items():
        print('.', end='')

        file_dict[size] = []
        for trr, file, file_offset in group:
            print('.', end='')
            full_path_client = get_full_client_path_for_torrent_file(trr, file)
            try:
                file_is_complete = file.progress == 1
                complete_file_exists = os.path.isfile(full_path_client)
                incomplete_file_exists = os.path.isfile(
                    full_path_client + '.!qB')

                # print(f't{trr.hash[:4]}f{file["id"]}')
                if not file_is_complete and complete_file_exists:
                    logger.warning(
                        'incomplete but some other file exists and appears full %s', file.name)
                if file_is_complete and incomplete_file_exists:
                    logger.warning(
                        'complete file but some incomplete file exists too %s', file.name)
                if file_is_complete and not complete_file_exists:
                    logger.warning(
                        'file complete but does not exist %s', file.name)

                if not file_is_complete:
                    if not full_path_client.lower().endswith('.!qb'):
                        full_path_client += '.!qB'
                    file_exists = incomplete_file_exists
                else:
                    file_exists = complete_file_exists

            except Exception as err:
                logger.error('Cant find file because of %s', err)
                continue
            # print('\n--')
            # logger.info(full_path_client)
            # logger.info('isc %s cfe %s ife %s', file_is_complete, \
            # complete_file_exists, incomplete_file_exists )
            piece_size = trr.properties.piece_size
            filesize = file.size
            pieces_offset = -(file_offset % piece_size)

            pieces_start = file.piece_range[0]
            pieces_end = file.piece_range[1]

            all_states = np.asarray(trr.piece_states, dtype=np.byte)
            piece_states = np.asarray(
                all_states[pieces_start:pieces_end+1], dtype=np.byte)

            ranges_completed = II.empty()

            for blocknum, status in enumerate(piece_states):
                if status == 2:
                    lower_bound = max(0, blocknum*piece_size + pieces_offset)
                    upper_bound = min(filesize, (blocknum+1) *
                                      piece_size + pieces_offset)
                    ranges_completed = ranges_completed | II.closedopen(
                        lower_bound, upper_bound)

            is_last_block_shared = (file_offset + file.size != trr.size) and \
                (((file_offset + file.size + 1) % piece_size) != 0)
            #pieces_offset = -(file_offset % trr.properties.piece_size)
            insert = {'file': file,
                      'torrent': trr,
                      'id': file['id'],
                      'hash': trr.hash,
                      'file_is_complete': file_is_complete,
                      'file_exists': file_exists,
                      'filename': file['name'],
                      'path_server': file['name'],
                      'full_path_client': full_path_client,
                      'is_last_file_in_torrent': (file.size + file_offset == trr.size),
                      'file_offset': file_offset,
                      'progress': file['progress'],
                      'debug': f't{trr.hash[:4]}f{file["id"]}',
                      'size': file.size,
                      'piece_size': trr.properties.piece_size,
                      'pieces_start': pieces_start,
                      'pieces_end': pieces_end,
                      'pieces_offset': pieces_offset,
                      'piece_states': piece_states,
                      'pieces_updated': [],
                      'piece_states_recheck': [],

                      'ranges_complete': ranges_completed,
                      'ranges_updated': II.empty(),
                      'ranges_needed': II.closedopen(0, filesize) - ranges_completed,

                      'first_block_shared': (pieces_offset < 0),
                      'last_block_shared': is_last_block_shared,

                      }

            file_dict[size].append(insert)
    print()
    return file_dict

def construct_file_dict_from_size_dict(sizes_dict):

    filedict = {}
    for size, files in sizes_dict.items():
        for file in files:
            if file.parent_hash != 'file':
                continue

            if size not in filedict:
                filedict[size] = []

            fileinfo = {
                'size': size,
                'filename': file.path,
                'full_path_client': file.path,
                'ranges_complete': II.closedopen(0, size),
            }
            filedict[size].append(fileinfo)
    return filedict

def scan_local_discs(dirs):
    logger.info('scanning dirs and building sizes dict')
    filedict = {}
    extensions = ['.mkv', '.mp4', '.m4v', '.wmv', '.avi', '.mpg']
    if args.min_size:
        min_file_size = args.min_size * 1024*1024
    else:
        min_file_size = config.getint('behaviour', 'min_file_size') * 1024*1024

    for dir in dirs:
        for path, _, files in os.walk(dir):
            for file in files:

                print('.', end='')
                ext = file[-4:]
                if ext not in extensions:
                    continue

                file_path = os.path.join(path, file)
                try:
                    size = os.path.getsize(file_path)
                except Exception as err:
                    logger.error('Error getting size of %s', file_path)
                    logger.error(err)
                    continue

                if size < min_file_size:
                    continue

                if size not in filedict:
                    filedict[size] = []
                fileinfo = {
                    'size': size,
                    'filename': file,
                    'full_path_client': file_path,
                    'ranges_complete': II.closedopen(0, size),
                }
                filedict[size].append(fileinfo)
    print()
    return filedict


def filter_only_common_sizes(local_files, torrent_files):
    logger.info('matching %s file sizes to %s torrent file sizes',
                len(local_files), len(torrent_files))
    files = {}
    torrents = {}
    iterator = torrent_files
    if len(local_files) < len(torrent_files):
        iterator = local_files

    for size in iterator:
        if size in local_files and size in torrent_files:
            files[size] = local_files[size]
            torrents[size] = torrent_files[size]

    logger.info('Common sizes: %s', len(files))
    return (files, torrents)


def look_for_dupes_on_local_discs(files, torrents):
    count_total = 0
    count = 0
    print('Counting possible matches')
    for size in torrents:
        for trr_file in torrents[size]:
            for local_file in files[size]:
                count_total +=1

    matches = []
    for size in torrents:
        for trr_file in torrents[size]:
            for local_file in files[size]:
                count+=1
                print(f'Pair {count} of {count_total} ', end ='\r')
                if find_blocks_in_other_file(trr_file, local_file):
                    print()
                    pair_info = do_something_with_match(trr_file, local_file)
                    matches.append((trr_file, local_file, pair_info))
    return matches


def do_something_with_match(trr_file, local_file):
    print('--------------')
    #print('possible match')
    print(f"torrent {trr_file['torrent'].name}")
    print(f'file: {trr_file["filename"]}')
#    print(f'local file: {local_file["filename"]}')
    print(f'local file: {local_file["full_path_client"]}')

    blocks_verified = False
    recheck = False

    if not args.auto and not args.later:
        answer = ''
        while answer not in ['l', 'n', 'a', 'v']:
            answer = input('(v)erify (n)ot (l)ater (a)uto now ?>').lower()
        if answer == 'a':
            args.auto = True
        elif answer == 'v':
            recheck = True
        elif answer == 'l':
            args.later = True

    if args.auto or args.later or args.verify:
        recheck = True

    if recheck:
#return (good_blocks, new_good_blocks, bad_blocks, new_bad_blocks, first_bad, last_bad)        
        blocks_verified = recheck_file_full(
            trr_file, client=args.qbt_client, alt_file=local_file['full_path_client'])


    unmark = False
    answer = ''

    if args.auto:
        print('blocks verified', blocks_verified)
        max_bad = 0
        if blocks_verified[4]:
            max_bad +=1
        if blocks_verified[5]:
            max_bad +=1

        if blocks_verified[2] <= max_bad:
            answer = 'u'
            print('Auto unmark')
        else:
            answer = 's'
            print('Auto skip')

    if not args.later:
        while answer not in ['n', 'a', 'u', 'l', 's', 'r']:
            answer = input(
                '(u)nmark download (n)ot (s)kip (l)ater (a)uto now (r)epair download using this file ?>').lower()
        if answer == 'a':
            args.auto = True
        elif answer == 'u':
            unmark = True
        elif answer == 'l':
            args.later = True
        elif answer == 'r':
            repair_torrent_using_local_file(trr_file, local_file)

    if unmark:
        args.qbt_client.torrents_file_priority(
            torrent_hash=trr_file['hash'],
            file_ids=trr_file['id'],
            priority=0)

    pair_info = {
        'blocks_verified': blocks_verified,
        'unmarked': unmark,
        'process_later': args.later
    }

    return pair_info


def repair_torrent_using_local_file(trr_file, local_file):
    logger.debug('looking for file %s',trr_file['full_path_client'])
    if os.path.isfile(trr_file['full_path_client']) is False:
        logger.info('Torrent file doesnt even exist, copying')
        try:
            path_to_make, _ = os.path.split(trr_file['full_path_client'])
            os.makedirs(path_to_make, exist_ok=True)
            shutil.copy(local_file['full_path_client'], trr_file['full_path_client'])
        except Exception as err:
            logger.error('error copying file')
            logger.error(err)
            return False

        logger.info('Forcing recheck')
        args.qbt_client.torrents_recheck(torrent_hashes=trr_file['hash'])
        return True

    if not trr_file['piece_states_recheck']:
        if not recheck_file_full(trr_file, client=args.qbt_client, alt_file=local_file['full_path_client']):
            return False

    local_file['piece_states'] = trr_file['piece_states_recheck']
    piece_size = trr_file['piece_size']
    pieces_offset = trr_file['pieces_offset']
    filesize = trr_file['size']

    
    ranges_completed = II.empty()
    for blocknum, status in enumerate(local_file['piece_states']):
        if status == 2:
            lower_bound = max(0, blocknum*piece_size + pieces_offset)
            upper_bound = min(filesize, (blocknum+1) *
                              piece_size + pieces_offset)
            ranges_completed = ranges_completed | II.closedopen(
                lower_bound, upper_bound)

    logger.debug(ranges_completed)
    local_file['ranges_complete'] = ranges_completed
    local_file['first_block_shared'] = trr_file['first_block_shared']
    local_file['last_block_shared'] = trr_file['last_block_shared']
    local_file['debug'] = ' LF'
    # print(local_file)

    num_blocks_fixed = 0
    blocks_fixed = []
    for blocknum, status in enumerate(trr_file['piece_states']):
        if status != 2:
            rebuilt = rebuild_block(trr_file, blocknum, [local_file])
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

    if num_blocks_fixed > 0:
        logger.info('Forcing recheck')
        args.qbt_client.torrents_recheck(torrent_hashes=trr_file['hash'])


def main():
    print(args.dirs)
    logger.info('Connecting to server')
    qbt_client = connect_qbt()
    args.qbt_client = qbt_client
    logger.info('Retrieving torrent info')
    if args.process_all:
        torrents = qbt_client.torrents_info()
    else:
        torrents = qbt_client.torrents_info(filter='resumed')
    # torrents = qbt_client.torrents_info(torrent_hashes=test_hashes)

    torrents = filterout_nometa_and_completeds(torrents)

    dict_of_sizes, filtered_hashes = get_sizes_dict(torrents, args.dirs)
    del torrents
    torrents = qbt_client.torrents_info(torrent_hashes=filtered_hashes)

    logger.info('Got torrents')

    dict_params = {
        'tg_regex': args.tg_regex,
        'filemax': 0,
    }

    logger.info('scanning directories')

    local_files = construct_file_dict_from_size_dict(dict_of_sizes)
    # local_files = scan_local_discs(args.dirs)
    logger.info('construct file dict')
    torrent_files = construct_file_dict(torrents, dict_params)

    local_files, torrent_files = filter_only_common_sizes(
        local_files, torrent_files)
    torrent_files = construct_file_dict_raw_part2(torrent_files)

    matches = look_for_dupes_on_local_discs(local_files, torrent_files)

    for match in matches:
        info = match[2]
        trr_file = match[0]
        local_file = match[1]
        if info['process_later']:
            print('--------------')
            print('possible match')
            print(f'torrent: {trr_file["filename"]}')
            print(f'local file: {local_file["filename"]}')

            binfo = info['blocks_verified']
            if binfo:
                print(
                    f'{binfo[0]} good blocks {binfo[1]} new good, {binfo[2]} bad {binfo[3]} new bad')
            else:
                print('No verify attempted')

            unmark = False
            answer = ''
            while answer not in ['y', 'n', 'u', 's', 'r']:
                answer = input(
                    '(u)nmark download (s)kip, (r)epair download using this file ?>').lower()
            if answer in ['u', 'y']:
                unmark = True
            elif answer == 'r':
                repair_torrent_using_local_file(trr_file, local_file)

            if unmark:
                args.qbt_client.torrents_file_priority(
                    torrent_hash=trr_file['hash'],
                    file_ids=trr_file['id'],
                    priority=0)
            print()


if __name__ == "__main__":
    from argparse import ArgumentParser
    parser = ArgumentParser(
        description='Look for torrent data locally')

    parser.add_argument('dirs', type=str, nargs='+',
                        help='Directories to scan')

    parser.add_argument('-all', dest='process_all', default=False, action='store_true',
                        help='Inject into all, default - only resumed')

    parser.add_argument('-debug', dest='debug', action='store_true')

    parser.add_argument('-tg_regex', dest='tg_regex', default='', type=str)

    parser.add_argument('-auto', action='store_true',
                        help='auto undownload if only last and or first are bad')

    parser.add_argument('-l', '--later', dest ='later', action='store_true',
                        help='scan first, ask later')

    parser.add_argument('-v', '--verify', dest='verify', default=False, action='store_true',
                        help='Full verify found suspects')

    parser.add_argument('-s', '--min_size', dest='min_size', default=0, type =int,
                        help='min size in MiB to bother (override config)')

    parser.add_argument('-f', '--file_max', dest='file_max', default=0, type =int,
                        help='maximum number of files (for testing) to process')

    parser.add_argument('-disable_regex', action='store_true', default=False, help='Disable exclude regexes')

    args = parser.parse_args()


    if args.debug:
        logger.setLevel(logging.DEBUG)

    if args.dirs == ['all']:
        args.dirs = config.get('client', 'all_local_dirs').split(' ')

    for a_dir in args.dirs:
        if not os.path.isdir(a_dir):
            logger.error('No dir %s', a_dir)
            sys.exit(0)

    time_start = time.time()
    main()
    time_end = time.time()
    total_time = time_end - time_start
    print("\nExecution time: " + str(total_time))
