#!/usr/bin/env python -u

import hashlib
import os
import shutil
import time

import numpy as np
import qbittorrentapi


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
    logger.info('Processing %s torrents', len(torrents))
    for trr in torrents:
        print('_', end='')
        file_offset = 0
        #print(trr['state'], end=' ')
        if not args.process_all and trr['state'].lower().startswith('paused'):
            logger.debug('skipping paused %s', trr.name)
            continue

        for file in trr.files:
            size = file.size
            print('.', end='')

            skip = size < args.min_size
            skip = skip or file.priority == 0
            skip = skip or file.progress == 0
#            skip = skip or trr.properties.piece_size > file['completed']

            if skip:
                file_offset += size
                continue

            start = file.piece_range[0]
            end = file.piece_range[1]
            full_path_client = args.qbt_tempdir_client + file['name'] + '.!qB'
            insert = {'file': file,
                      'filename': file['name'],
                      'path_server': file['name'],
                      'full_path_client': full_path_client,
                      'id': file['id'],
                      'torrent': trr,
                      'hash': trr['hash'],
                      'piece_size': trr.properties.piece_size,
                      'pieces_start': start,
                      'pieces_end': end,
                      'offset': file_offset,
                      'progress': file['progress']
                      }

            if size not in files:
                files[size] = []
            files[size].append(insert)
            file_offset += size
    print()
    return files


def match_files_multi(files):
    merges = []
    while len(files) >= 2:
        file0 = files.pop()
        file0_and_clones = [file0]
        for file in reversed(files):
            if is_file_unique(file, file0_and_clones) and process2files(file0, file):
                file0_and_clones.append(file)
                files.remove(file)
        if len(file0_and_clones) > 1:
            merges.append(file0_and_clones)
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

        with open(file2['full_path_client'], 'rb') as fh2:
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
        logger.error('matching error')
        logger.error(
            'h1 %s f1 %s', file1['torrent'].hash, file1['full_path_client'])
        logger.error(
            'h2 %s f2 %s', file2['torrent'].hash, file2['full_path_client'])
        logger.error(err)
        return False

    return matches == 3

def is_file_unique(newfile, files):

    try:
        if not os.path.isfile(newfile['full_path_client']):
            logger.debug('file does not exist, so its unique %s', newfile['filename'])
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
    for group in merge_list:
        for file in group:
            hashes.add(file['torrent'].hash)
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


def extend_file(full_path_client, desired_size):
    logger.debug('Extending to %s bytes, %s', desired_size, full_path_client)

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

    logger.debug('Opening %s', full_path_client)
    try:
        with open(full_path_client, 'r+b') as fh:
            fh.seek(physical_size)
            while difference > args.buffer_size:
                fh.write(bytearray(args.buffer_size))
                difference -= args.buffer_size
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


def verify_physical_filesize(file):
    logger.debug('getting physical files sizes')
    try:
        f_size = os.path.getsize(file['full_path_client'])
    except Exception as err:
        logger.error(err)
        return False

    if f_size < file['file'].size:
        if not extend_file(file['full_path_client'], file['file'].size):
            return False
    return True


def merge_multi(files):
    hashes = []
    for file in files:
        hashes.append(file['hash'])
        if file['file'].size != files[0]['file'].size:
            logger.error('final file sizes mismatch %s %s',
                         files[0]['file'].size, file['file'].size)
            return False

    all_paused = False
    t_start = time.time()
    while not all_paused:

        if time.time() - t_start > args.timeout:
            logger.error('torrents not paused timeout')
            print('Torrents not paused timeout')
            answer = 'null'
            while answer.lower() not in ['r', 'a', 'i']:
                answer = input('(r)etry pausing, (i)gnore pausing, (s)kip').lower()

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
            all_paused = all_paused and trr['state'].lower().startswith('paused')
        if not all_paused:
            args.qbt_client.torrents_pause(hashes=hashes)
            time.sleep(5)

    for file in files:
        if not verify_physical_filesize(file):
            return False

    if args.hardmerge:
        hard_merge(files)
    elif args.maxmerge:
        max_merge(files)
    else:
        logger.error('section disabled')

def max_merge(files, direction='all'):
    logger.debug('opening files')
    fhs = []
    try:
        for file in files:
            fhs.append(open(file['full_path_client'], 'rb+'))
    except Exception as err:
        logger.error(err)
        return False

    block_num = 0
    total_blocks = int((files[0]['file'].size - 1) / args.buffer_size) + 1
    for file in files:
        print(file['file']['name'])

    print(
        f'Processing {size_to_dib(files[0]["file"].size)} in {size_to_dib(args.buffer_size)} blocks')
    try:
        all_done = False
        while True:
            if block_num < total_blocks:
                print(f'Block {block_num+1} of {total_blocks}   \r', end='')

            block = None
            block_is_first = True
            for fh in fhs:
                fh.seek(block_num*args.buffer_size, 0)
                buffer = fh.read(args.buffer_size)
                if len(buffer) == 0:
                    all_done = True
                    break
                if block_is_first:
                    block = np.frombuffer(buffer, dtype=np.ubyte, count=-1)
                    block_is_first = False
                else:
                    block = np.fmax(block, np.frombuffer(
                        buffer, dtype=np.ubyte, count=-1))
            if all_done:
                break

            for count, fh in enumerate(fhs, 1):
                if direction in ['all', f'to{str(count)}']:
                    logger.debug('writing block to file %s', count)
                    fh.seek(block_num*args.buffer_size, 0)
                    fh.write(block.tobytes())
            block_num += 1
    except Exception as err:
        print()
        logger.error(err)
        for fh in fhs:
            fh.close()
        return False

    print()
    for fh in fhs:
        fh.close()
    return True

def swap_files_inplace(file1, file2):
    temp_file = os.path.join(args.merge_dir_client, 'temp_swap_file')
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

def hard_merge(files):
    logger.debug('Starting hard merge')
    time_now = int(time.time())

    # first merge into most complete file
    files.sort(key = lambda x: x['progress'], reverse=True)
    file0 = files[0]

    answer = args.auto_yes
    answer = answer or input('Merge MAX first?') == 'y'

    if answer:
        logger.info('merging %s files into %s', len(files), file0['filename'])
        for file in files:
            print(file['hash'])
            print(file['filename'])
            print(file['full_path_client'])
            print()

        if not max_merge(files, direction='to1'):
            logger.debug('max merge pre hard merge fail')
            return False
        logger.debug('max pre hard success')

    #second use biggest torrent as parent
    files.sort(key = lambda x: x['torrent'].size, reverse=True)
    file_parent = files.pop(0)

    final_dest = file_parent['path_server']
    logger.debug('final dest %s', final_dest)

    input(' PAUSE ')
    if file0 != file_parent:
        swap_files_inplace(file0, file_parent)

    #point torrents to parent and stash obsolete files
    for file in files:
        logger.debug('moving %s to', file['filename'])
        new_path_client = os.path.join(args.merge_dir_client, file['hash'])
        new_path_client = os.path.join(new_path_client, file['filename'])
        logger.debug(new_path_client)

        dir_to_make, _ = os.path.split(new_path_client)
        os.makedirs(dir_to_make, exist_ok=True)
        shutil.move(file['full_path_client'], new_path_client)
        logger.debug('file moved')

        new_path_server = final_dest
        print(new_path_client)
        print(new_path_server)
        with open(
                os.path.join(args.merge_dir_client, f'log_{time_now}.txt')\
                    , 'a', encoding='utf-8') as fh:

            fh.writelines(f'''
---------
epoch: {int(time.time())}
hash1: {file['hash']}
torrent1: {file['torrent'].name}
file1: {file['filename']}
old path: {file['full_path_client']}
new path: {new_path_client}
new path server: {new_path_server}
dest: {final_dest}

        ''')

        logger.info('Renaming file in qbittorrent')
        args.qbt_client.torrents_rename_file(
            torrent_hash=file['hash'], file_id=file['id'],
            old_path=file['path_server'],
            new_path=final_dest
        )
        args.qbt_client.torrents_add_tags(torrent_hashes=file['hash'], tags='_ram_clone')

        if file['torrent'].size < 2 *1024*1024*1024:
            args.qbt_client.torrents_resume([file['hash']])
            args.qbt_client.torrents_recheck([file['hash']])

    args.qbt_client.torrents_add_tags(torrent_hashes=file_parent['hash'], tags='_ram_parent')
    if file_parent['torrent'].size < 2 *1024*1024*1024:
        args.qbt_client.torrents_resume([file_parent['hash']])
        args.qbt_client.torrents_recheck([file_parent['hash']])

    return True


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
        new_size = int(new_size / 1024)
        index += 1
    new_size = str(new_size) + [' KiB', ' MiB', ' GiB', ' TiB'][index]
    return new_size


def main():
    logger.info('Connecting to server')
    qbt_client = connect_qb()
    args.qbt_client = qbt_client
    logger.info('Retrieving torrent info - all files')
    torrents = qbt_client.torrents_info()# hashes=test_hashes)
    logger.info('Got torrents')

    logger.info('filter no meta')
    torrents = filter_no_meta(torrents)
    # logger.info('filter no pieces')
    # torrents = filter_no_pieces(torrents)
    logger.info('construct file dict')
    file_dict = construct_file_dict(torrents)

    merge_list = []
    for _, files in file_dict.items():
        files_to_merge = match_files_multi(files)
        merge_list.extend(files_to_merge)

    print('pairs or mores', len(merge_list))
    # print(merge_list)
    hashes = get_unique_hashes(merge_list)
    print('unique torrents', len(hashes))
    #decision = input('Enter to start merging')
    print('pausing torrents')
    qbt_client.torrents_pause(hashes)

    print('Merge start')

    for group in merge_list:
        merge_multi(group)
    print('resuming torrents')
    qbt_client.torrents_resume(hashes)
    print('forcing rechecks')
    qbt_client.torrents_recheck(hashes)

    # time.sleep(10)


if __name__ == "__main__":

    import logging
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    sh = logging.StreamHandler()
    sh.setLevel(logging.DEBUG)
    sh.setFormatter(formatter)
    logger.addHandler(sh)

    from argparse import ArgumentParser
    parser = ArgumentParser(
        description='delete active torrents automagically if other copy is completed.')

    parser.add_argument('-tdc', dest='qbt_tempdir_client', default='q:\\tt\\',
                        help='qbittorrent temporary directory from server perspective')

    parser.add_argument('-s', dest='min_size', default=50,
                        type=int, help='min size of file to process in MB')

    parser.add_argument('-m', dest='min_gain', default=2, type=int,
                        help='Minimum blocks to gain default = 2')

    parser.add_argument('-all', dest='process_all', default=False, action='store_true',
                        help='Inject into paused files too, default false')

    parser.add_argument('-b', '--buffersize', dest='buffer_size', default=50, type=int,
        help='buffers (x2) MiB size for same disc read speed up default 50MiB == 100MiB required')

    parser.add_argument('-maxmerge', default=False, action='store_true',
        help='Perform full merge for SPARSE FILES ONLY, does array np.max(file1, file2)')

    parser.add_argument('-hardmerge', default=False, action='store_true',
                        help='Point both torrents to 3rd (possible merged) file')

    parser.add_argument('-mdc', dest='merge_dir_client', default='q:\\tt\\autoram\\', type=str,
                        help='dir for bekap, backrolls and merges visible locally')

    parser.add_argument('-mds', dest='merge_dir_server', default='autoram/', type=str,
                        help='dir for bekap, backrolls and merges visible on server')

    parser.add_argument('-debug', dest='debug', action='store_true')
    parser.add_argument('-yy', dest='auto_yes',
                        action='store_true', help='auto yes all')

    args = parser.parse_args()
    args.timeout = 60

    args.buffer_size = args.buffer_size * 1024 * 1024
    args.min_size *= 1024*1024
    if args.debug:
        logger.setLevel(logging.DEBUG)
    time_start = time.time()
    main()
    time_end = time.time()
    total_time = time_end - time_start
    print("\nExecution time: " + str(total_time))
