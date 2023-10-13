#!/usr/bin/env python -u
import configparser
import logging
import logging.config
import os
import re
import time

import numpy as np

from autoram.files_on_disk import recheck_file, recheck_file_full
from autoram.qbt_api import connect_qbt
from autoram.ranges import II
from autoram.tr_payload import filter_no_meta, find_blocks_in_other_file

logging.config.fileConfig('logging.conf')
logger = logging.getLogger(__name__)

config = configparser.ConfigParser()
config.read('autoram.ini')


def construct_file_dict(torrents, dict_params):
    reg_exclude = config.get('behaviour', 'nono_regex')
    filemax = dict_params['filemax']
    torrents = filter_no_meta(torrents)
    file_dict_raw = {}
    logger.info('Processing %s torrents', len(torrents))
    logger.info('Building sizes dictionary')
    count_files = 0
    min_file_size = config.getint('behaviour', 'min_file_size') * 1024*1024

    for trr in torrents:
        print('_', end='')
        file_offset = 0

        if filemax and count_files >= filemax:
            logger.debug('filemax of %s hit', filemax)
            break

        for file in trr.files:
            count_files += 1
            size = file.size
            print('.', end='')

            skip = False
            skip = skip or file.priority == 0
            skip = skip or size < min_file_size
            skip = skip or re.search(reg_exclude, file.name)
            if skip:
                file_offset += size
                continue

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
            full_path_client = config['client']['qbt_tempdir'] + file['name']
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

                      'ranges_complete': ranges_completed,
                      'ranges_updated': II.empty(),
                      'ranges_needed': II.closedopen(0, filesize) - ranges_completed,

                      'first_block_shared': (pieces_offset < 0),
                      'last_block_shared': is_last_block_shared,

                      }

            file_dict[size].append(insert)
    print()
    return file_dict


def scan_local_discs(dirs):
    logger.info('scanning dirs and building sizes dict')
    filedict = {}
    extensions = ['.mkv', '.mp4', '.m4v', '.wmv', '.avi', '.mpg']
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
    matches = []
    for size in torrents:
        for trr_file in torrents[size]:
            for local_file in files[size]:
                if find_blocks_in_other_file(trr_file, local_file):
                    pair_info = do_something_with_match(trr_file, local_file)
                    matches.append((trr_file, local_file, pair_info))
    return matches


def do_something_with_match(trr_file, local_file):
    print('--------------')
    print('possible match')
    print(f'torrent: {trr_file["filename"]}')
    print(f'local file: {local_file["filename"]}')

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

    if (args.auto or args.later) and args.verify:
        recheck = True

    if recheck:
        trr_file['full_path_client'] = local_file['full_path_client']
        blocks_verified = recheck_file_full(trr_file, client=args.qbt_client)

    unmark = False
    if not args.auto and not args.later:
        answer = ''
        while answer not in ['n', 'a', 'u', 'l']:
            answer = input(
                '(u)nmark download (n)ot (s)kip (l)ater (a)uto now ?>').lower()
        if answer == 'a':
            args.auto = True
        elif answer == 'u':
            unmark = True
        elif answer == 'l':
            args.later = True

    if args.auto:
        unmark = True

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

    logger.info('scanning directories')

    local_files = scan_local_discs(args.dirs)
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
            while answer not in ['y', 'n', 'u']:
                answer = input('(u)nmark download (n)ot ?>').lower()
            if answer in ['u', 'y']:
                unmark = True

            if unmark:
                args.qbt_client.torrents_file_priority(
                    torrent_hash=trr_file['hash'],
                    file_ids=trr_file['id'],
                    priority=0)
            print()


if __name__ == "__main__":
    from argparse import ArgumentParser
    parser = ArgumentParser(
        description='Look for torrent files in local files')

    parser.add_argument('dirs', type=str, nargs='+', help='Directories to scan')


    parser.add_argument('-all', dest='process_all', default=False, action='store_true',
                        help='Inject into paused files too, default false')

    parser.add_argument('-debug', dest='debug', action='store_true')

    parser.add_argument('-tg_regex', dest='tg_regex', default='', type=str)

    parser.add_argument('-auto', action='store_true',
                        help='autoresolve (un-download)')

    parser.add_argument('-later', action='store_true',
                        help='scan first, ask later')

    parser.add_argument('-stop', action='store_true', default=False,
                        help='Auto stop downloads when file found')

    parser.add_argument('-verify', default=False, action='store_true',
                        help='Full verify found suspects')

    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    time_start = time.time()
    main()
    time_end = time.time()
    total_time = time_end - time_start
    print("\nExecution time: " + str(total_time))
