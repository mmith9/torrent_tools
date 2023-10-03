import configparser
import logging
import logging.config
import os
import re
import numpy as np
from autoram.ranges import II

logging.config.fileConfig('logging.conf')
logger = logging.getLogger(__name__)

config = configparser.ConfigParser()
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


def construct_file_dict(torrents, dict_params):
    reg_exclude = config.get('behaviour','nono_regex')
    reg_targets = dict_params['tg_regex']
    filemax = dict_params['filemax']

    torrents = filter_no_meta(torrents)
    file_dict_raw = {}
    targets = []
    logger.info('Processing %s torrents', len(torrents))
    logger.info('Sorting by size')
    count_files = 0
    min_file_size = config.getint('behaviour', 'min_file_size') *1024*1024

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
            #skip = skip or file.priority == 0
            skip = skip or size < min_file_size
            skip = skip or re.search(reg_exclude, file.name)
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
    for _ , file, _ in targets:
        target_sizes.add(file.size)

    logger.debug('looking for size %s', target_sizes)
    for size, group in file_dict_raw.items():
        print('.', end = '')
        if target_sizes and size not in target_sizes:
            continue
        if len(group) < 2:
            continue
        # print(f'\n{size}', end='')

        file_dict[size] = []
        for trr, file, file_offset in group:
            print('.', end='')
            full_path_client = config['client']['qbt_tempdir'] + file['name']
            try:
                file_is_complete = file.progress == 1
                complete_file_exists = os.path.isfile(full_path_client)
                incomplete_file_exists = os.path.isfile(full_path_client + '.!qB')

                # print(f't{trr.hash[:4]}f{file["id"]}')
                if not file_is_complete and complete_file_exists:
                    logger.warning('incomplete but some other file exists and appears full %s', file.name)
                if file_is_complete and incomplete_file_exists:
                    logger.warning('complete file but some incomplete file exists too %s', file.name)
                if file_is_complete and not complete_file_exists:
                    logger.warning('file complete but does not exist %s', file.name)

                if not file_is_complete:
                    full_path_client+= '.!qB'
                    file_exists = incomplete_file_exists
                else:
                    file_exists = complete_file_exists
               
            except Exception as err:
                logger.error('Cant find file because of %s', err)
                continue
            # print('\n--')
            # logger.info(full_path_client)
            # logger.info('isc %s cfe %s ife %s', file_is_complete, complete_file_exists, incomplete_file_exists )
            piece_size = trr.properties.piece_size
            filesize = file.size
            pieces_offset = -(file_offset % piece_size)

            pieces_start = file.piece_range[0]
            pieces_end = file.piece_range[1]
    
            all_states = np.asarray(trr.piece_states, dtype=np.byte)
            piece_states = np.asarray(all_states[pieces_start:pieces_end+1], dtype=np.byte)
   
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
    return file_dict

