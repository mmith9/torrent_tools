#!/usr/bin/env python -u

import hashlib
import os
import time
import re
import sys
import qbittorrentapi
import mysql.connector
import numpy as np


def connect_qb():
    qbt_client = qbittorrentapi.Client(
        host='192.168.2.202',
        port=8070,
        username='admin',
        password=''
    )

    try:
        qbt_client.auth_log_in()
    except qbittorrentapi.LoginFailed as err:
        print(err)
    return qbt_client


def filter_no_meta(torrents):
    gots_meta = []
    for trr in torrents:
        if trr.size > 0:
            gots_meta.append(trr)
    return gots_meta


def filter_no_pieces(torrents):
    gots_pieces = []
    for trr in torrents:
        if max(trr.pieceStates) > 1:
            gots_pieces.append(trr)
    return gots_pieces


def construct_file_dict(torrents):
    files = {}
    trr_count = 0
    for trr in torrents:
        print('_', end='')
        trr_count += 1
        file_offset = 0
        file_count = 0
        for file in trr.files:
            size = file.size
            print('.', end='')
            if size < args.min_size:
                file_offset += size
                continue

            if file.priority == 0:
                file_offset += size
                continue

            if file.progress > 0.999:
                file_offset += size
                continue

            start = file.piece_range[0]
            end = file.piece_range[1]
            full_path = args.qbt_tempdir + file['name'] + '.!qB'
            insert = {'file': file,
                      'full_path': full_path,
                      'torrent': trr,
                      'piece_size': trr.properties.piece_size,
                      'pieces_start': start,
                      'pieces_end': end,
                      'offset': file_offset
                      }

            if size not in files:
                files[size] = []
            files[size].append(insert)
            file_offset += size

    return files


def match_files(files):
    merges = []
    while len(files) >= 2:
        file1 = files.pop()
        for file2 in files:
            if file1['full_path'] != file2['full_path']:
                if process2files(file1, file2):
                    merges.append((file1, file2))
    return merges


def scale_pieces(pieces, ratio):
    if ratio < 2:
        return pieces
    return np.repeat(pieces, ratio)


def extract_piece_info(file):
    all_pieces = np.array(file['torrent'].piece_states, dtype=np.byte)
    file['pieces'] = all_pieces[file['pieces_start']:file['pieces_end']+1]


def match_file1_to_file2(file1, file2, f2_scaled_pieces):
    duoblocks_found = 0
    duoblocks = []

    prev_status = 0
    f2_pieces = enumerate(f2_scaled_pieces)

    for blocknum, status in f2_pieces:
        if prev_status == 2 and status == 2:
            duoblocks.append(blocknum-1)
            duoblocks_found += 1
            if duoblocks_found >= 3:
                break
        prev_status = status

    if duoblocks_found < 3:
        return False

    matches = 0
    blocksize = file1['piece_size']
    f1_offset = (blocksize - file1['offset'] % blocksize) % blocksize

    f1_hash_offset = file1['pieces_start']
    if f1_offset > 0:
        f1_hash_offset += 1

    print('------------')
    print(file1['file']['name'])
    print('pieces start', file1['pieces_start'], 'byte offset',
          f1_offset, 'piece offset', f1_hash_offset, 'blocksize', size_to_dib(blocksize))
    print('---')
    print(file2['file']['name'])
    print('pieces start', file2['pieces_start'], 'byte offset',
          file2['offset'], 'blocksize', size_to_dib(file2['piece_size']))

    try:

        with open(file2['full_path'], 'rb') as fh2:
            for duoblock in duoblocks:
                fh2.seek(f1_offset + duoblock*blocksize)
                piece = fh2.read(blocksize)
                f1_hash = file1['torrent'].piece_hashes[duoblock+f1_hash_offset]
                f2_hash = hashlib.sha1(piece).hexdigest()

                print('block', duoblock, end=' ')
                # print(f1_hash)
                # print(f2_hash, end=' ')
                # print(f2_hash in file1['torrent'].piece_hashes,  end=' ')

                if f1_hash.lower() == f2_hash.lower():
                    matches += 1
                    print(' match')
                else:
                    print(' no match')

    except Exception as err:
        logger.error(err)
        return False

    return matches == 3


def process2files(file1, file2):

    extract_piece_info(file1)
    if max(file1['pieces']) < 2:
        return False
    if min(file1['pieces']) > 1:
        return False
    extract_piece_info(file2)
    if max(file2['pieces']) < 2:
        return False
    if min(file1['pieces']) > 1:
        return False

    if file1['piece_size'] > file2['piece_size']:
        file1, file2 = (file2, file1)

    ratio = int(file2['piece_size'] / file1['piece_size'])
    f2_scaled_pieces = scale_pieces(file2['pieces'], ratio)

    while len(file1["pieces"]) < len(f2_scaled_pieces):
        f2_scaled_pieces = f2_scaled_pieces[:-1]

    while len(file1["pieces"]) > len(f2_scaled_pieces):
        f2_scaled_pieces = np.append(f2_scaled_pieces, 0)

    if not match_file1_to_file2(file1, file2, f2_scaled_pieces):
        return False

    # print(f'f1 pieces {len(file1["pieces"])} vs f2 {len(f2_scaled_pieces)}')
    # print()

    # print(file1['pieces'])
    # print(file2['pieces'])
    # print(f2_scaled_pieces)

    diff = np.mod(file1['pieces'] + f2_scaled_pieces, 4)
    diff_num = np.count_nonzero(diff)
    print('potential pieces to gain', diff_num)

    # decision = input('merge?')
    # if decision == 'y':
    #     merge2files(file1, file2, f2_scaled_pieces)

    return diff_num > args.min_gain


def get_unique_hashes(merge_list):
    hashes = set()
    for f1, f2 in merge_list:
        hashes.add(f1['torrent'].hash)
        hashes.add(f2['torrent'].hash)
    return list(hashes)


def extract_ranges(file):
    ranges = []
    offset = file['offset']
    first_block = file['pieces_start']
    last_block = file['pieces_end']
    blocksize = file['piece_size']
    filesize = file['file'].size
    file_stats = file['pieces']

    if offset > 0:
        offset = (blocksize - (offset % blocksize)) % blocksize

    last_stat = 0
    if offset > 0:
        stat = file_stats[0]
        file_stats = np.delete(file_stats, 0)
        if stat == 2:
            ranges.append([0, offset])
            last_stat = stat

    for blocknum, stat in enumerate(file_stats):
        if stat == 2:
            if last_stat == 2:
                ranges[-1][1] += blocksize
            else:
                ranges.append([offset+blocknum*blocksize,
                              offset+(blocknum+1)*blocksize])
        last_stat = stat

    if ranges:
        ranges[-1][1] = min(filesize, ranges[-1][1])

    return ranges


def substract_ranges(ranges1_, ranges2_):
    # real copy
    ranges1 = ranges1_[:]
    ranges2 = ranges2_[:]
    ranges = []

    # print(ranges1_)
    # print(ranges2_)
    # print(ranges1)
    # print(ranges2)

    if not ranges1:
        return ranges
    if not ranges2:
        return ranges1

    r1 = ranges1.pop(0)
    r2 = ranges2.pop(0)

    while True:

        # purposefully ignoring touching ranges
        # all sets are <x,y)
        # as it's only 1 byte difference for read and write

        # r1 disjoint on left
        if r1[1] <= r2[0]:
            ranges.append(r1)
            if ranges1:
                r1 = ranges1.pop(0)
                continue
            return ranges

        # r1 disjoint on right
        if r1[0] >= r2[1]:
            if ranges2:
                r2 = ranges2.pop(0)
                continue
            ranges.append(r1)
            return ranges

        # r1 is subset of r2
        if r1[0] >= r2[0] and r1[1] <= r2[1]:
            if ranges1:
                r1 = ranges1.pop(0)
                continue
            return ranges

        # r1 is superset of r2
        if r1[0] <= r2[0] and r1[1] >= r2[1]:
            if r1[0] < r2[0]:
                ranges.append([r1[0], r2[0]])
            if r1[1] == r2[1]:
                if not ranges2:
                    ranges.extend(ranges1)
                    return ranges
                if not ranges1:
                    return ranges
                r1 = ranges1.pop(0)
                r2 = ranges2.pop(0)
                continue
            r1[0] = r2[1]
            if ranges2:
                r2 = ranges2.pop(0)
                continue
            ranges.append(r1)
            ranges.extend(ranges1)
            return ranges

        # r1 right side overlaps r2
        if r1[0] <= r2[0] and r1[1] <= r2[1]:
            r1[1] = r2[0]
            ranges.append(r1)
            if ranges1:
                r1 = ranges1.pop(0)
                continue
            return ranges

        # r1 left side overlaps r2
        if r1[0] >= r2[0] and r1[1] >= r2[1]:
            if r1[1] == r2[1]:
                if ranges1:
                    r1 = ranges1.pop(0)
                    continue
                return ranges

            r1[0] = r2[1]
            if ranges2:
                r2 = ranges2.pop(0)
                continue
            ranges.append(r1)
            return ranges

        logger.error('invalid path in range substraction')
        assert False


def merge_pairs(pairs):
    for file1, file2 in pairs:
        f1_ranges = extract_ranges(file1)
        f2_ranges = extract_ranges(file2)

        f1_ranges_dif = substract_ranges(f1_ranges, f2_ranges)
        f2_ranges_dif = substract_ranges(f2_ranges, f1_ranges)

        print(file1['file']['name'])
        print(len(f1_ranges))
        print(file2['file']['name'])
        print(len(f2_ranges))
        print('--')
        print(len(f1_ranges_dif))
        print('--')
        print(len(f2_ranges_dif))

        try:
            with open(file1['full_path'], 'r+b') as fh1:
                with open(file2['full_path'], 'r+b') as fh2:
                    copy_ranges(fh1, fh2, f1_ranges_dif)
                    copy_ranges(fh2, fh1, f2_ranges_dif)
        except Exception as err:
            logger.error(err)


def copy_ranges(fh1, fh2, ranges):
    for start, end in ranges:
        fh1.seek(start)
        chunk = fh1.read(end - start)
        fh2.seek(start)
        fh2.write(chunk)
        print('.', end='')
    print()


def size_to_dib(size):
    index = 0
    new_size = int(size / 1024)
    while new_size > 1024:
        new_size = int(size / 1024)
        index += 1
    new_size = str(new_size) + [' KiB', ' MiB', ' GiB', ' TiB'][index]
    return new_size


def main():
    logger.info('Connecting to server')
    qbt_client = connect_qb()
    logger.info('Retrieving torrent info')
    torrents = qbt_client.torrents_info(status_filter='resumed')
    logger.info('Got torrents')

    logger.info('filter no meta')
    torrents = filter_no_meta(torrents)
    # logger.info('filter no pieces')
    # torrents = filter_no_pieces(torrents)
    logger.info('construct file dict')
    file_dict = construct_file_dict(torrents)

    merge_list = []
    for _, files in file_dict.items():
        pairs_to_merge = match_files(files)
        merge_list.extend(pairs_to_merge)

    print('pairs ', len(merge_list))
    # print(merge_list)
    hashes = get_unique_hashes(merge_list)
    print('unique torrents', len(hashes))
    #decision = input('Enter to start merging')
    print('pausing torrents')
    qbt_client.torrents_pause(hashes)

    time.sleep(10)
    print('Merge start')

    merge_pairs(merge_list)
    print('resuming torrents')
    qbt_client.torrents_resume(hashes)
    print('forcing rechecks')
    qbt_client.torrents_recheck(hashes)

    time.sleep(10)


if __name__ == "__main__":

    import logging
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    # fh = logging.FileHandler(__name__ + '.txt')
    # fh.setLevel(logging.DEBUG)
    # fh.setFormatter(formatter)
    sh = logging.StreamHandler()
    sh.setLevel(logging.DEBUG)
    # sh.setFormatter(formatter)
    # logger.addHandler(fh)

    logger.addHandler(sh)

    import pprint
    pprinter = pprint.PrettyPrinter()

    from argparse import ArgumentParser

    parser = ArgumentParser(
        description='delete active torrents automagically if other copy is completed.')

    parser.add_argument('-d', dest='qbt_tempdir', default='q:\\tt\\',
                        help='qbittorrent temporary directory')

    parser.add_argument('-s', dest='min_size', default=50,
                        type=int, help='min size of file to process in MB')

    parser.add_argument('-m', dest='min_gain', default=2,
                        help='Minimum blocks to gain default = 2')

    args = parser.parse_args()

    args.min_size *= 1024*1024

    time_start = time.time()
    main()
    time_end = time.time()
    total_time = time_end - time_start
    print("\nExecution time: " + str(total_time))
