import configparser
import hashlib
import logging
import logging.config
import os
import re
import time
from typing import Any, List, Tuple
from autoram.klasses import FileOfSize

import numpy as np

from autoram.files_on_disk import get_full_client_path_for_torrent_file, is_physical_file_unique, scan_tree
from autoram.ranges import II

logging.config.fileConfig('logging.conf')
logger = logging.getLogger(__name__)
print(__name__)

config = configparser.ConfigParser(allow_no_value=True, delimiters='=')
config.read('autoram.ini')

def filter_no_meta(torrents):
    gots_meta = []
    for trr in torrents:
        if trr.state.startswith('error'):
            continue
        if trr.size <= 0:
            continue

        gots_meta.append(trr)
    return gots_meta


def filter_no_pieces(torrents):
    gots_pieces = []
    for trr in torrents:
        if max(trr.pieceStates) > 1:
            gots_pieces.append(trr)
    return gots_pieces

def construct_file_dict(torrents, dict_params, disable_regex):
    reg_exclude = config.get('behaviour', 'nono_regex')
    reg_targets = dict_params['tg_regex']
    filemax = dict_params['filemax']

    torrents = filter_no_meta(torrents)
    file_dict_raw = {}
    targets = []
    logger.info('Processing %s torrents', len(torrents))
    logger.info('Building sizes dictionary')
    count_files = 0
    min_file_size = config.getint('behaviour', 'min_file_size') * 1024*1024

    count_total = len(torrents)
    count=0

    for trr in torrents:
        count+=1
        file_offset = 0

        if filemax and count_files >= filemax:
            logger.debug('filemax of %s hit', filemax)
            break

        for file in trr.files:
            count_files += 1
            print(f'\r{count} of {count_total} trrs {count_files} files', end='')
            size = file.size

            skip = False
            #skip = skip or file.priority == 0
            skip = skip or size < min_file_size
            skip = skip or (not disable_regex and  re.search(reg_exclude, file.name))
            if skip:
                file_offset += size
                continue

            insert = (trr, file, file_offset)
            if reg_targets:
                if re.search(reg_targets, file.name):
                    targets.append(insert)

            if size not in file_dict_raw:
                file_dict_raw[size] = []

            file_dict_raw[size].append(insert)
            file_offset += size
    print()
    return construct_file_dict_raw_part2(file_dict_raw, targets)


def construct_file_dict_raw_part2(file_dict_raw, targets):
    logger.info('Grouping by size, %s sizes', len(file_dict_raw))
    file_dict = {}

    target_sizes = set()
    for _, file, _ in targets:
        target_sizes.add(file.size)

    logger.debug('Extracting full info about groups of 2 and more')
    count_total = len(file_dict_raw.items())
    count=0
    for size, group in file_dict_raw.items():
        count+=1
        print('\r                                                                     ', end='')
        print(f'\r{count} of {count_total}', end='')
        if target_sizes and size not in target_sizes:
            continue
        if len(group) < 2:
            continue
        # print(f'\n{size}', end='')

        file_dict[size] = []
        for trr, file, file_offset in group:
            print('.', end='')
            full_path_client = get_full_client_path_for_torrent_file(trr, file)
            file_is_complete = file.progress == 1
            file_exists = os.path.isfile(full_path_client)

            # try:
            #     complete_file_exists = os.path.isfile(full_path_client)
            #     incomplete_file_exists = os.path.isfile(full_path_client)

            #     # print(f't{trr.hash[:4]}f{file["id"]}')
            #     if not file_is_complete and complete_file_exists:
            #         logger.warning(
            #             'incomplete but some other file exists and appears full %s', file.name)
            #     if file_is_complete and incomplete_file_exists:
            #         logger.warning(
            #             'complete file but some incomplete file exists too %s', file.name)
            #     if file_is_complete and not complete_file_exists:
            #         logger.warning(
            #             'file complete but does not exist %s', file.name)

            #     if not file_is_complete:
            #         full_path_client += '.!qB'
            #         file_exists = incomplete_file_exists
            #     else:
            #         file_exists = complete_file_exists

            # except Exception as err:
            #     logger.error('Cant find file because of %s', err)
            #     continue
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
                      'category': trr.category,

                      'ranges_complete': ranges_completed,
                      'ranges_updated': II.empty(),
                      'ranges_needed': II.closedopen(0, filesize) - ranges_completed,

                      'first_block_shared': (pieces_offset < 0),
                      'last_block_shared': is_last_block_shared,

                      }

            file_dict[size].append(insert)
    print()
    return file_dict


def match_same_size_files_multi(files_of_same_size):
    files = files_of_same_size
    # logger.debug('matching %s files of size %s', len(files), files[0]['size'])
    files.sort(key=lambda x: x['progress'])
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

    # logger.debug('trying to match harder')
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

    # logger.debug('grouping of %s done, groups found %s', size, len(groups))
    return groups


def is_file_unique_to_group(file0, files):
    is_unique = True
    if file0['file_exists']:
        is_unique = is_physical_file_unique(file0, files)
    else:
        for file in files:
            is_unique = is_unique and file0['path_server'] != file['path_server']
    return is_unique


def file_belongs_to_group(file0, group):
    for file in group:
        if find_blocks_in_other_file(file0, file):
            return True
        if find_blocks_in_other_file(file, file0):
            return True
    return False


def find_blocks_in_other_file(file1, file2):
    # logger.debug('looking for >%s>%s', file1['debug'], file1['filename'])
    # logger.debug('offset %s blocksize %s', file1['file_offset'], size_to_dib(file1['piece_size']))
    # logger.debug('in         >%s>%s', file2['debug'], file2['filename'])
    # logger.debug('offset %s blocksize %s', file2['file_offset'], size_to_dib(file2['piece_size']))

    if not os.path.isfile(file2['full_path_client']):
        logger.error('file2 %s not found', file2['full_path_client'])
        return False

    ranges = file2['ranges_complete']
    logger.debug('file2 ranges %s', ranges)
    # logger.debug('got %s ranges', len(ranges))
    if not ranges:
        logger.info('ranges empty')
        return False

#    print('comparing blocks')
    piece_size = file1['piece_size']
#    print('piece size', piece_size)
    file_offset = file1['file_offset']
#    print('file offset', file_offset)

    pieces_offset = file1['pieces_offset']
#    print('piece offset', pieces_offset)

    pieces_start = file1['pieces_start']
    torrent_hashes = file1['torrent'].piece_hashes

    blocknum = 0
    if pieces_offset < 0:
        blocknum = 1

    padded_blocks_found = 0
    blocks_found = 0
    tries = 0
    max_tries = 10
    while (blocknum+1)*piece_size + pieces_offset < file1['size']:
        if tries >= max_tries:
            logger.debug('Failed %s times, skipping', max_tries)
            return False

        byte_start = blocknum*piece_size + pieces_offset
        byte_end = (blocknum+1)*piece_size + pieces_offset

        block_range = II.closedopen(byte_start, byte_end)
        logger.debug('seeking range %s', block_range)
        if block_range not in ranges:
            blocknum += 1
            continue

        hash1 = torrent_hashes[blocknum + pieces_start]
        logger.debug('%s hash read %s', hash1, blocknum + pieces_start)

        try:
            with open(file2['full_path_client'], 'rb') as fh:
                fh.seek(byte_start)
                piece_data = fh.read(piece_size)
                hash2 = hashlib.sha1(piece_data).hexdigest()


                if pieces_offset !=0:
                    fh.seek(blocknum*piece_size)
                    piece_data = fh.read(piece_size)
                    hash_padded = hashlib.sha1(piece_data).hexdigest()
                else:
                    hash_padded = hash2

            logger.debug('%s computed: %s', hash2, blocknum)
        except Exception as err:
            logger.error(err)
            tries += 1
            time.sleep(5)
            continue

        blocknum += 1
        # logger.info('need hash %s', hash1)
        # logger.info('computed  %s', hash2)
        # logger.info('if padded %s', hash_padded)

        if hash1.lower() == hash2.lower():
            blocks_found += 1
        elif hash1.lower() == hash_padded.lower():
            padded_blocks_found+=1
        else:
            tries += 1

        if blocks_found >= 3:
            return True
        elif padded_blocks_found >=3:
            logger.warning('Found blocks but file is padded, setting offset to 0')
            file1['pieces_offset'] = 0
            return True

    print('end, false')
    return False

def filterout_nometa_and_completeds(torrents: list) -> list:
    torrents_filtered = []
    total = len(torrents)
    count = 0
    for trr in torrents:
        count += 1
        print(f'quick filter {count} of {total} torrents ', end='\r')       
        if trr.size <= 0 or trr.amount_left <=0:
            continue
        torrents_filtered.append(trr)
    print()
    return torrents_filtered



def get_sizes_dict(torrents: list, dirs: str) -> Tuple[dict, list]:
    sizes = {}
    logger.info('scanning dirs')
    add_sizes_dict_dirs(sizes, dirs)
    logger.info('scanning torrents')
    add_sizes_dict_qbt(sizes, torrents)


    logger.info('filtering usable sizes from %s sizes', len(sizes))
    hashes = set()
    usable_sizes = {}
    for size, files in sizes.items():

        if len(files) <= 1:
            continue

        if count_existing_files(files) == 0:
            continue

        usable_sizes[size] = files
        for file in files:
            hashes.add(file.parent_hash)
    logger.info('Usable sizes found %s from %s torrents',
                len(usable_sizes), len(hashes))
    return (usable_sizes, hashes)


def add_sizes_dict_qbt(sizes: dict, torrents: list) -> None:
    min_file_size = config.getint('behaviour', 'min_file_size') * 1024**2
    total = len(torrents)
    count = 0

    for trr in torrents:
        count += 1
        if trr.size <= 0 or trr.amount_left <=0:
            continue
        
        print(f'Extracting sizes {count} of {total} torrents ', end='\r')
        for file in trr.files:
            if file.size < min_file_size:
                continue
            if file.priority == 0:
                continue

            if file.size not in sizes:
                sizes[file.size] = []
            file_path = get_full_client_path_for_torrent_file(trr, file)
            sizes[file.size].append(FileOfSize(
                size=file.size, path=file_path, parent_hash=trr.hash))
    print()


def add_sizes_dict_dirs(sizes: dict, dirs: list) -> None:
    min_file_size = config.getint('behaviour', 'min_file_size') * 1024**2
    reg_exclude = '^alwaysfalse$' if args.disable_regex else config.get('behaviour', 'nono_regex')

    if len(dirs) == 1 and dirs[0] == 'all':
        dirs = config.get('client', 'all_local_dirs').split(' ')

    for dir_ in dirs:
        print(f'scanning {dir_}')
        count = 0
        for entry in scan_tree(dir_):
            count += 1
            print(f'{count} files ', end='\r')
            if not entry.is_file:
                continue

            file_size = entry.stat(follow_symlinks=False).st_size
            if file_size < min_file_size:
                continue

            if re.search(reg_exclude, entry.path):
                #print(f'excluding {entry.path}')
                continue

            if file_size not in sizes:
                sizes[file_size] = []

            sizes[file_size].append(FileOfSize(
                size=file_size, path=entry.path, parent_hash='file'))
        print()


def count_existing_files(files: List[FileOfSize]) -> int:
    count = 0
    for file in files:
        if file.parent_hash == 'file':
            count += 1
            continue

        if os.path.isfile(file.path):
            count += 1
        # print(count, end=' ')
    return count
