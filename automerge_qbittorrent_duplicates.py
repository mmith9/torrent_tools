#!/usr/bin/env python -u

import hashlib
import os
import shutil
import time

import numpy as np
import portion as P
import qbittorrentapi


class IntInterval(P.AbstractDiscreteInterval):
    _step = 1


II = P.create_api(IntInterval)


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


def construct_file_dict(torrents, filemax=0):
    files = {}
    logger.info('Processing %s torrents', len(torrents))
    count_files = 0
    trr_num = 0
    for trr in torrents:
        if filemax and count_files >= filemax:
          # logger.debug('filremax of %s hit', filemax)
            break
        trr_num += 1
        print('_', end='')
        file_offset = 0
        #print(trr['state'], end=' ')
        if not args.process_all and trr['state'].lower().startswith('paused'):
            logger.debug('skipping paused %s', trr.name)
            continue

        file_num = 0
        for file in trr.files:
            count_files += 1
            file_num += 1
            size = file.size
            print('.', end='')

            skip = size < args.min_size
#            skip = skip or file.priority == 0
#            skip = skip or file.progress == 0
#            skip = skip or trr.properties.piece_size > file['completed']

            if skip:
                file_offset += size
                continue

            full_path_client = args.qbt_tempdir_client + file['name']
            if not os.path.isfile(full_path_client):
                full_path_client += '.!qB'
                if not args.allow_dummies and not os.path.isfile(full_path_client):
                    continue

            insert = {'file': file,
                      'filename': file['name'],
                      'path_server': file['name'],
                      'full_path_client': full_path_client,
                      'id': file['id'],
                      'torrent': trr,

                      'piece_size': trr.properties.piece_size,
                      'pieces_start': file.piece_range[0],
                      'pieces_end': file.piece_range[1],
                      'offset': file_offset,
                      'progress': file['progress'],
                      'size': file.size,
                      'debug': f'tnum {trr_num} fnum {file_num}',
                      'dummy': 'unknown',
                      'byteranges': II.empty(),
                      'ranges_updated': II.empty(),
                      'ranges_needed': II.closedopen(0, file.size),
                      }

            if size not in files:
                files[size] = []
            files[size].append(insert)
            file_offset += size
    print()
    return files


def find_blocks_in_other_file(file1, file2):
    # logger.debug('looking for>%s>%s', file1['debug'], file1['filename'])
    # logger.debug('offset %s blocksize %s', file1['offset'], size_to_dib(file1['piece_size']))
    # logger.debug('in         >%s>%s', file2['debug'], file2['filename'])
    # logger.debug('offset %s blocksize %s', file2['offset'], size_to_dib(file2['piece_size']))
    
    if not os.path.isfile(file2['full_path_client']):
      # logger.debug('file2 not found')
        return False

    ranges = extract_byte_ranges(file2)
    # logger.debug('got %s ranges', len(ranges))
    if not ranges:
        # logger.debug('ranges empty')
        return False

    piece_size = file1['piece_size']
    file_offset = file1['offset']
    piece_offset = -(file_offset % piece_size)

    pieces_start = file1['pieces_start']
    torrent_hashes = file1['torrent'].piece_hashes

    blocknum = 0
    if piece_offset <0:
        blocknum = 1

    blocks_found = 0
    tries = 0
    max_tries = 10
    while (blocknum+1)*piece_size + piece_offset < file1['size']:
        if tries >= max_tries:
          # logger.debug('Failed %s times, skipping', max_tries)
            return False
        
        byte_start = blocknum*piece_size + piece_offset
        byte_end = (blocknum+1)*piece_size + piece_offset

        block_range = II.closedopen(byte_start, byte_end)
        if block_range not in ranges:
            blocknum +=1
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
            tries +=1
        if blocks_found >= 3:
            return True
    return False

def recheck_file(file):
    logger.debug('----- RECHECK -----')
  # logger.debug('looking for>%s>%s', file['debug'], file['filename'])
  # logger.debug('offset %s blocksize %s', file['offset'], size_to_dib(file['piece_size']))
    
    if not os.path.isfile(file['full_path_client']):
      # logger.debug('file to recheck not found')
        return False

    piece_size = file['piece_size']
    file_offset = file['offset']
    piece_offset = -(file_offset % piece_size)
    pieces_start = file['pieces_start']
    pieces_end = file['pieces_end']

    torrent_pieces = np.array(file['torrent'].piece_states, dtype=np.byte)
    file_pieces = torrent_pieces[pieces_start:pieces_end+1]

    torrent_hashes = file['torrent'].piece_hashes
    new_ranges = file['ranges_updated'] | file['byteranges']
    

    blocknum = 0
    if piece_offset <0:
        blocknum = 1

    new_blocks_found = 0
    while (blocknum+1)*piece_size + piece_offset < file['size']:

        piece_status = file_pieces[blocknum]
        if piece_status == 2:
            print('o', end='')
            blocknum += 1
            continue
        else:
            print('?', end='')
                
        byte_start = blocknum*piece_size + piece_offset
        byte_end = (blocknum+1)*piece_size + piece_offset

        block_range = II.closedopen(byte_start, byte_end)
        if not args.maxmerge and block_range not in new_ranges:
            print('\b.', end ='')
            blocknum +=1
            continue

        hash1 = torrent_hashes[blocknum + pieces_start]
    #    logger.debug('%s hash read %s', hash1, blocknum + pieces_start)

        with open(file['full_path_client'], 'rb') as fh:
            fh.seek(byte_start)
            piece_data = fh.read(piece_size)
            hash2 = hashlib.sha1(piece_data).hexdigest()
        # logger.debug('%s computed: %s', hash2, blocknum)

        blocknum += 1
        if hash1.lower() == hash2.lower():
            new_blocks_found += 1
            if block_range in new_ranges:
                print('\bB', end='')
            else:
                print('\bM', end='')
        else:
            if block_range in new_ranges:
                print('\bb', end='')
            else:
                print('\bm', end='')

    print('\n')
    logger.info('new blocks found %s', new_blocks_found)
    return False

def extract_byte_ranges(file):
    if file['byteranges']:
        #logger.debug('no need to extract ranges again')
        return file['byteranges']

    file_offset = file['offset']
    piece_size = file['piece_size']
    filesize = file['file'].size

    all_pieces = np.array(file['torrent'].piece_states, dtype=np.byte)
    file_pieces = all_pieces[file['pieces_start']:file['pieces_end']+1]

    piece_offset = -(file_offset % piece_size)
    
    ranges = II.empty()
    #print('blockstates ', end ='')
    for blocknum, stat in enumerate(file_pieces):
        if stat == 2:
            #print('_', end='')
            lower_bound = max(0, blocknum*piece_size + piece_offset)
            upper_bound = min(filesize, (blocknum+1)*piece_size + piece_offset)
            ranges = ranges | II.closedopen(lower_bound, upper_bound)
        else:
            #print('.', end='')
            pass
    file['byteranges'] = ranges
    #print()
    return ranges




def file_belongs_to_group(file0, group):
    for file in group:
        if find_blocks_in_other_file(file0, file):
            return True
        if find_blocks_in_other_file(file, file0):
            return True
    return False


def match_same_size_files_multi(files_of_same_size):
    files = files_of_same_size.copy()
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

  # logger.debug('grouping done')
    print('Total groups', len(groups))
    for group in groups:
        print()
        for file in group:
            print(f"'{file['torrent'].hash}', ", end="")
    print()
    return groups


def is_file_unique(newfile, files):

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


def get_unique_hashes(merge_list):
    hashes = set()
    for group in merge_list:
        for file in group:
            hashes.add(file['torrent'].hash)
    return list(hashes)


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

        if time.time() - t_start > args.timeout:
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

    if args.hardmerge:
        hard_merge(files)
    elif args.maxmerge:
        max_merge(files)
    else:
        block_merge(files)


def max_merge(files, direction='all', ranges=False):
  # logger.debug('max merge with %s files direction %s', len(files), direction)
    file0 = files[0]
    if direction == 'to1' and file0['dummy'] == 'dummy':
        logger.error('Cant merge to dummy file %s', )
        return False

    fhs = []
    try:
        for file in files:
            if file['dummy'] != 'dummy':
                fhs.append(open(file['full_path_client'], 'rb+'))
    except Exception as err:
        logger.error(err)
        return False

    block_num = 0
    total_blocks = int((files[0]['file'].size - 1) / args.buffer_size) + 1
    for file in files:
        print('file ', file['debug'], file['filename'])

    print(
        f'Proccing {size_to_dib(files[0]["file"].size)} in {size_to_dib(args.buffer_size)} blocks')
    try:
        all_done = False
        while True:
            if block_num < total_blocks:
                print(f'Block {block_num+1} of {total_blocks}')

            block = None
            block_is_first = True
            for num, fh in enumerate(fhs, 1):
              # logger.debug('reading file %s', num)
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
                  # logger.debug('writing block to file %s', count)
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

def block_merge(files, direction='all'):
    logger.debug('BLOCK merge with %s files direction %s', len(files), direction)

    source_files = []
    for file in files:
        if file['dummy'] != 'dummy':
            source_files.append(file)

    if len(source_files) < 2:
      # logger.debug('nothing to merge')
        return False

    if direction == 'to1':
        if files[0] == source_files[0]:
            target_files = [files[0]]
        else:
          # logger.debug('target file was dummy')
            return False
    else:
        target_files =source_files.copy()
        
    try:
        for tg_file in target_files:
            full_file_ranges = II.closedopen(0, tg_file['size'])
            tg_ranges = extract_byte_ranges(tg_file)
            ranges_needed = full_file_ranges - tg_ranges
            ranges_updated = II.empty()
          # logger.debug('tg file %s', tg_file['debug'])
            for src_file in source_files:
              # logger.debug('src file %s', src_file['debug'])
                if src_file == tg_file:
                    continue
                        
                src_ranges = extract_byte_ranges(src_file)
                cpy_ranges = src_ranges - tg_ranges
                #print('target has', tg_ranges)
                #print('source has', src_ranges)
                print('usable ranges   ', cpy_ranges)
                if not cpy_ranges:
                  # logger.debug('no ranges to copy from %s to %s', src_file['debug'], tg_file['debug'])
                    pass

                copy_ranges(tg_file, src_file, cpy_ranges)
                tg_ranges = tg_ranges | cpy_ranges
                ranges_needed = ranges_needed - cpy_ranges
                ranges_updated = ranges_updated | cpy_ranges

                if args.maxmerge:
                    logger.debug('----- MAX MERGE TOO ----')
                    copy_ranges_max(tg_file, src_file, ranges_needed)


            full_file_ranges = II.closedopen(0, tg_file['size'])

            tg_file['ranges_updated'] = ranges_updated

            tg_file['ranges_needed'] = ranges_needed - ranges_updated

            if not tg_file['ranges_needed']:
                logger.info('file should be complete, %s', tg_file['filename'])

            if args.verify:
                recheck_file(tg_file)

    except Exception as err:
        logger.error('Error while processing')
        logger.error('tg_file %s>%s', tg_file['debug'], tg_file['filename'])
        logger.error('src_file %s>%s', src_file['debug'], src_file['filename'])
        logger.error(err)
        logger.error('----------------------')
        return False

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
  # logger.debug('hard merge with %s files', len(files))
    time_now = int(time.time())

    existing_files = []
    for file in files:
        if file['dummy'] != 'dummy':
            existing_files.append(file)

    if len(existing_files) >1:
        # first merge into most complete file
        existing_files.sort(key=lambda x: x['progress'], reverse=True)
        file0 = existing_files[0]


        if args.blockmerge:
            logger.debug('-------- BLOCK MERGE ----------')
            block_merge(files, direction='to1')


    # second use biggest torrent as parent
    existing_files.sort(key=lambda x: x['torrent'].size, reverse=True)
    file_parent = existing_files.pop(0)

    final_dest = file_parent['path_server']
  # logger.debug('final dest %s', final_dest)

  # logger.debug('skipping hard merging for now')
    return False
    input(' PAUSE ')
    input(' PAUSE ')
    input(' PAUSE ')

    if file0 != file_parent:
        swap_files_inplace(file0, file_parent)

    # point torrents to parent and stash obsolete files
    for file in files:
        if file['dummy'] != 'dummy':
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
                os.path.join(args.merge_dir_client, f'log_{time_now}.txt'), 'a', encoding='utf-8') as fh:

            fh.writelines(f'''
---------
is dummy: {file['dummy']}
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
        args.qbt_client.torrents_add_tags(
            torrent_hashes=file['hash'], tags='_ram_clone')

        if file['torrent'].size < 2 * 1024*1024*1024:
            args.qbt_client.torrents_resume([file['hash']])
            args.qbt_client.torrents_recheck([file['hash']])

    args.qbt_client.torrents_add_tags(
        torrent_hashes=file_parent['hash'], tags='_ram_parent')
    if file_parent['torrent'].size < 2 * 1024*1024*1024:
        args.qbt_client.torrents_resume([file_parent['hash']])
        args.qbt_client.torrents_recheck([file_parent['hash']])

    return True


def copy_ranges(target, source, ranges):
  # logger.debug('opening target')
    with open(target['full_path_client'], 'rb+') as fh_tg:
        logger.debug('opening source file')
        with open(source['full_path_client'], 'rb') as fh_src:
            for range_ in ranges:
                start = range_.lower
                end = range_.upper +1
                fh_src.seek(start)
                fh_tg.seek(start)
                bytes_left = end - start
                while bytes_left >0:
                    buffersize = min(bytes_left, args.buffer_size)
                  # logger.debug('copying %s bytes from %s to %s', buffersize, source['debug'], target['debug'])
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
                end = range_.upper +1
                fh_src.seek(start)
                fh_tg.seek(start)
                src_file_pos = start
                bytes_left = end - start
                while bytes_left >0:
                    buffersize = min(bytes_left, args.buffer_size)
                  # logger.debug('copying %s bytes from %s to %s', buffersize, source['debug'], target['debug'])
                    data_chunk1 = fh_src.read(buffersize)
                    data_chunk2 = fh_tg.read(buffersize)

                    data_array1 = np.frombuffer(data_chunk1, dtype=np.ubyte, count=-1)
                    data_array2 = np.frombuffer(data_chunk2, dtype=np.ubyte, count=-1)
                    data_array_max = np.fmax(data_array1, data_array2)

                    fh_tg.seek(src_file_pos)
                    fh_tg.write(data_array_max.tobytes())

                    bytes_left -= buffersize
                    src_file_pos += buffersize


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


    torrents = qbt_client.torrents_info()#hashes=test_hashes)
    
    
    logger.info('Got torrents')

    logger.info('filter no meta')
    torrents = filter_no_meta(torrents)
    # logger.info('filter no pieces')
    # torrents = filter_no_pieces(torrents)
    logger.info('construct file dict')
    file_dict = construct_file_dict(torrents, filemax = 0)

    merge_list = []
    for _, files in file_dict.items():
        if len(files) > 1:
            groups_to_merge = match_same_size_files_multi(files)
            merge_list.extend(groups_to_merge)

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
      # logger.debug('merging group of %s', len(group))
        merge_multi(group)
    # print('resuming torrents')
    # qbt_client.torrents_resume(hashes)
    # print('forcing rechecks')
    # qbt_client.torrents_recheck(hashes)

    # time.sleep(10)


if __name__ == "__main__":

    import logging
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    #formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    formatter = logging.Formatter(
        '%(asctime)s> %(levelname)s> %(message)s', '%H:%M:%S')
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

    parser.add_argument('-retry', dest='max_retries', default=5, type=int,
                        help='Keep looking for valid pieces if hash was bad default 5 times')

    parser.add_argument('-maxmerge', default=False, action='store_true',
                        help='Perform full merge for SPARSE FILES ONLY, does array np.max(file1, file2)')

    parser.add_argument('-hardmerge', default=False, action='store_true',
                        help='Point both torrents to 3rd (possible merged) file')

    parser.add_argument('-blockmerge', default=False, action='store_true',
                        help='perform blockmerge')


    parser.add_argument('-mdc', dest='merge_dir_client', default='q:\\tt\\autoram\\', type=str,
                        help='dir for bekap, backrolls and merges visible locally')

    parser.add_argument('-mds', dest='merge_dir_server', default='autoram/', type=str,
                        help='dir for bekap, backrolls and merges visible on server')

  
    parser.add_argument('-verify', default=False, action='store_true',
                        help='Check if any new blocks appeared')


    parser.add_argument('-debug', dest='debug', action='store_true')
    parser.add_argument('-yy', dest='auto_yes',
                        action='store_true', help='auto yes all')
    parser.add_argument('-dummy', dest='allow_dummies', default=False,
                        action='store_true', help='allow creation of empty files')

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
