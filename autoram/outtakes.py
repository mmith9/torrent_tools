

def hard_merge(files):
  # logger.debug('hard merge with %s files', len(files))
    time_now = int(time.time())

    existing_files = []
    for file in files:
        if file['dummy'] != 'dummy':
            existing_files.append(file)

    if len(existing_files) > 1:
        # first merge into most complete file
        existing_files.sort(key=lambda x: x['progress'], reverse=True)
        file0 = existing_files[0]

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
            new_path_client = os.path.join(
                config['client']['qbt_tempdir'], file['hash'])
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
                os.path.join(config['client']['qbt_tempdir'],
                             f'log_{time_now}.txt'), 'a', encoding='utf-8') as fh:

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
    total_blocks = int((files[0]['file'].size - 1) / config['behaviour']['buffer_size']) + 1
    for file in files:
        print('file ', file['debug'], file['filename'])

    print(
        f'Proccing {size_to_dib(files[0]["file"].size)} in {size_to_dib(config["behaviour"]["buffer_size"])} blocks')
    try:
        all_done = False
        while True:
            if block_num < total_blocks:
                print(f'Block {block_num+1} of {total_blocks}')

            block = None
            block_is_first = True
            for num, fh in enumerate(fhs, 1):
              # logger.debug('reading file %s', num)
                fh.seek(block_num*config['behaviour']['buffer_size'], 0)
                buffer = fh.read(config['behaviour']['buffer_size'])
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
                    fh.seek(block_num*config['behaviour']['buffer_size'], 0)
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
    logger.debug('BLOCK merge with %s files direction %s',
                 len(files), direction)

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
        target_files = source_files.copy()

    try:
        for tg_file in target_files:
            full_file_ranges = II.closedopen(0, tg_file['size'])
            tg_ranges = tg_file['byteranges']
            ranges_needed = full_file_ranges - tg_ranges
            ranges_updated = II.empty()
          # logger.debug('tg file %s', tg_file['debug'])
            for src_file in source_files:
              # logger.debug('src file %s', src_file['debug'])
                if src_file == tg_file:
                    continue

                src_ranges = src_file['byteranges']
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


def new_merge(files, direction='to1'):
    logger.debug('BLOCK merge with %s files direction %s',
                 len(files), direction)

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
        target_files = source_files.copy()

    try:
        for tg_file in target_files:
            full_file_ranges = II.closedopen(0, tg_file['size'])
            tg_ranges = tg_file['ranges_complete']
            ranges_needed = full_file_ranges - tg_ranges
            ranges_updated = II.empty()
          # logger.debug('tg file %s', tg_file['debug'])
            for src_file in source_files:
              # logger.debug('src file %s', src_file['debug'])
                if src_file == tg_file:
                    continue

                src_ranges = src_file['ranges_complete']
                cpy_ranges = src_ranges - tg_ranges
                #print('target has', tg_ranges)
                #print('source has', src_ranges)
                print('usable ranges   ', cpy_ranges)
                if not cpy_ranges:
                  # logger.debug('no ranges to copy from %s to %s',\
                  #  src_file['debug'], tg_file['debug'])
                    pass

                copy_ranges(tg_file, src_file, cpy_ranges)
                tg_ranges = tg_ranges | cpy_ranges
                ranges_needed = ranges_needed - cpy_ranges
                ranges_updated = ranges_updated | cpy_ranges

                if args.hammer:
                    logger.debug('----- hammer ----')
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