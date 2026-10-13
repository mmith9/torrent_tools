


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