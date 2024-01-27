#!/usr/bin/env python

import functools
import os
import sys
import time
import binascii
from typing import List
import random
import tempfile
import sqlite3
import keyboard
import mysql.connector
import libtorrent
import my_torrent_stuff

VERSION = "0.0.1"


class Counter:
    def __init__(self) -> None:
        self.names = ['new', 'old', 'resolved', 'offloaded']
        self.values = {}
        for name in self.names:
            self.values[name] = 0

    def increase(self, what: str, value: int):
        self.values[what] += value

    def value_of(self, what: str) -> int:
        return self.values[what]


class Job:
    def __init__(self):
        self.id = 0
        self.handle = None
        self.total_runtime = 0
        self.session_runtime = 0
        self.hexhash: str

    def is_complete(self):
        ret = True
        try:
            status = self.handle.status()
            ret = ret and status.has_metadata
    #        ret = ret and status.last_seen_complete > 0
    #        ret = ret and status.list_seeds > 0
    #        ret = ret and status.list_peers > 0
        except (RuntimeError) as err:
            logger.critical('err in torrent %s', self.hexhash)
            logger.critical('error:')
            logger.critical('%s', err)
            return False
        return ret

    def get_status(self):
        try:
            status = self.handle.status()
        except (RuntimeError) as err:
            logger.critical('err in torrent %s', self.hexhash)
            logger.critical('error:')
            logger.critical('%s', err)
            return False
        return status

    def has_meta(self):
        status = self.get_status()
        if status:
            return status.has_metadata
        else:
            return False

    def is_timeout(self):
        status = self.get_status()
        if status:
            return status.active_time > self.session_runtime + args.timeout
        else:
            return False

    def is_aged(self):
        status = self.get_status()
        if status:
            return (status.active_time) > args.aged
        else:
            return False

    def just_die(self, session_handle):
        status = self.get_status()
        if status:
            self.session_runtime = status.active_time
        else:
            self.session_runtime = -1
        session_handle.remove_torrent(self.handle)
        return

    def reap_data(self):
        output = {}
        logger.debug('reaping completed job')
        status = self.handle.status()
        output['id'] = self.id
        output['name'] = status.name
        output['last_seen_complete'] = status.last_seen_complete
        output['peers'] = status.list_peers
        output['seeds'] = status.list_seeds
        output['hexhash'] = self.hexhash

        torinfo = self.handle.torrent_file()
        files = torinfo.files()
        output['num_files'] = files.num_files()
        output['file_list'] = []
        for i in range(files.num_files()):
            output['file_list'].append(
                [files.file_path(i), files.file_size(i)])
        return output

    def reap_torrent_file(self):
        try:
            step1 = self.handle.status()
            step2 = step1.torrent_file
            step3 = libtorrent.create_torrent(step2)
            step4 = step3.generate()
            step5 = libtorrent.bencode(step4)
            return step5
        except RuntimeError as err:
            print('\nRuntime error')
            print(err)
            return False

    def go_to_sleep(self):
        logger.debug('Job going to sleep')
        self.handle.pause()

    def wake_up(self):
        logger.debug('Job waking up')
        self.handle.resume()
        status = self.handle.status()
        self.session_runtime = status.active_time


class Trackers:
    def __init__(self) -> None:
        self.list = []
        self.num = 0

    def load_from_file(self, filename: str) -> None:
        f_h = open(filename, "r", encoding='utf-8')
        trackers = f_h.readlines()
        f_h.close()
        for row in trackers:
            self.list.append(
                {'url': row.strip('\n'), 'uses': 0, 'resolves': 0, 'ratio': 0})
        self.num = len(self.list)

    def load_from_db(self, cursor, protocols):
        if 'udp' and 'tcp' in protocols:
            query = 'select url, uses, resolves, ratio from trackers '
        elif 'udp' in protocols:
            query = 'select url, uses, resolves, ratio from trackers where url like "udp%" '
        elif 'tcp' in protocols:
            query = 'select url, uses, resolves, ratio from trackers where url like "htt%" '
        else:
            logger.critical('No protocols (udp/tcp) defined')
            sys.exit()

        cursor.execute(query)
        rows = cursor.fetchall()
        for row in rows:
            self.list.append(
                {'url': row[0], 'uses': row[1], 'resolves': row[2], 'ratio': row[3]})
        self.num = len(self.list)

    def save_to_db(self, cursor):
        query_check = 'select count(1) from trackers '\
            'where url like (?) '

        query_update = 'update trackers set uses = (?), resolves = (?), ratio = (?) '\
            'where url like (?) '

        query_insert = 'insert into trackers (uses, resolves, ratio, url) '\
            'values (?, ?, ?, ?) '

        for tracker in self.list:
            cursor.execute(query_check, (tracker['url'],))
            row = cursor.fetchone()
            if row[0] > 0:
                cursor.execute(query_update,
                               (tracker['uses'], tracker['resolves'], tracker['ratio'], tracker['url']))
            else:
                print(tracker)
                cursor.execute(query_insert,
                               (tracker['uses'], tracker['resolves'], tracker['ratio'], tracker['url']))

    def get_random_url(self, amount: int) -> list:
        if amount < self.num:
            trackers = random.sample(self.list, amount)
        else:
            trackers = self.list

        url_list = []
        for tracker in trackers:
            #            tracker['uses'] +=1
            url_list.append(tracker['url'])

        return url_list

    def report_success(self, job: Job) -> None:
        trackers = job.handle.trackers()
        urls = []
        for tracker in trackers:
            urls.append(tracker['url'])
        for tracker in self.list:
            if tracker['url'] in urls:
                tracker['resolves'] += 1
                tracker['uses'] += 1
                tracker['ratio'] = tracker['resolves'] / tracker['uses']

    def report_failure(self, job: Job) -> None:
        trackers = job.handle.trackers()
        urls = []
        for tracker in trackers:
            urls.append(tracker['url'])
        for tracker in self.list:
            if tracker['url'] in urls:
                tracker['uses'] += 1
                tracker['ratio'] = tracker['resolves'] / tracker['uses']


class Resolver:
    def __init__(self) -> None:
        logger.debug('object initialization')

        self.last_job_spawn = 0
        self.jobs: List[Job]
        self.timeout_jobs: List[Job]
        self.jobs = []
        self.timeout_jobs = []
        self.trackers: List[str]
        self.trackers = []
        self.hashes_to_resolve = []
        self.count = Counter()
        logger.debug('connecting to db')
        mysql_database_name = "tpb"
        mysql_user = os.environ.get("mysql_user")
        mysql_password = os.environ.get("mysql_password")
        mysql_host = os.environ.get("mysql_host")
        self.trackers = Trackers()
        self.mysql_cursor = False
        self.mysql_connection = False
        keyboard.on_press(self.keyboard_event)
        keyboard.on_press_key('q', self.terminate_resolver)

        try:
            conn_sqlite3 = sqlite3.connect('resolver.sqlite')
            cursor_sqlite3 = conn_sqlite3.cursor()
        except sqlite3.Connection.Error:
            print('Error opening local resolver db')
            sys.exit(1)
        self.sqlite3cursor = cursor_sqlite3
        self.sqlite3connection = conn_sqlite3
        self.initialize_sqlite_db()

        if args.main_import:
            logger.info('Connecting to mysql')
            try:
                self.mysql_connection = mysql.connector.connect(
                    host=mysql_host,
                    user=mysql_user,
                    password=mysql_password,
                    database=mysql_database_name
                )
                self.mysql_cursor = self.mysql_connection.cursor()
            except mysql.connector.Error as err:
                logger.error('Connection to mysql db failed')
                print(err)
                sys.exit()
            self.import_from_mysql()

        logger.debug('initializing libtorrent session')
        self.protocols = ['udp', 'tcp']
        self.session_settings = libtorrent.default_settings()
        self.session_settings['listen_interfaces'] = '0.0.0.0:6818'
        self.session_settings['peer_fingerprint'] = 'non-default-finger-print'
        self.session_settings['announce_to_all_trackers'] = True  # False
        self.session_settings['validate_https_trackers'] = False  # true
        self.session_settings['tracker_completion_timeout'] = 30  # 30
        self.session_settings['connection_speed'] = 10  # 30
        self.session_settings['connections_limit'] = 500  # 200
        self.session_settings['listen_queue_size'] = 5  # 5
        self.session_settings['torrent_connect_boost'] = 3  # 30
        self.session_settings['max_concurrent_http_announces'] = 50  # 50
        # self.session_settings['dht_max_dht_items'] = 70000  # 700
        # self.session_settings['dht_max_torrent_search_reply'] = 50  # 20
        # self.session_settings['dht_block_ratelimit'] = 100  # 5
        # self.session_settings['dht_max_infohashes_sample_count'] = 50  # 20
        self.session_settings['prefer_udp_trackers'] = True
        self.session_settings['enable_outgoing_utp'] = 'udp' in self.protocols
        self.session_settings['enable_incoming_utp'] = 'udp' in self.protocols
        self.session_settings['enable_outgoing_tcp'] = 'tcp' in self.protocols
        self.session_settings['enable_incoming_tcp'] = 'tcp' in self.protocols

        self.lt_session = libtorrent.session()
        self.lt_session.apply_settings(self.session_settings)
        self.sessions_throttle = 0

        self.lt_params = libtorrent.add_torrent_params()
        ltflags = libtorrent.add_torrent_params_flags_t

        self.lt_params.flags &= ~ ltflags.flag_auto_managed
        self.lt_params.flags |= ltflags.flag_upload_mode

        # necessary as upload-only does not prevent creation of
        # empty files and directory structure under them
        self.tmpdir = tempfile.TemporaryDirectory()
        self.lt_params.save_path = self.tmpdir.name
        self.lt_params.storage_mode = libtorrent.storage_mode_t(2)
        self.lt_params.max_connections = 3

    def initialize_sqlite_db(self):
        logger.info('Initializing sqlite3')
        query1 = '''
            CREATE TABLE IF NOT EXISTS `hashes_to_resolve` (
            `id` integer PRIMARY KEY,
            `infohash` char(40) UNIQUE
            )  '''

        query2 = '''
            CREATE TABLE IF NOT EXISTS `old_hashes_to_resolve` (
            `id` integer PRIMARY KEY,
            `infohash` char(40) UNIQUE,
            `runtime` integer NOT NULL DEFAULT '0'
            )'''

        query3 = '''
            CREATE TABLE IF NOT EXISTS `trackers` (
            `id` integer PRIMARY KEY,
            `url` char(250) UNIQUE,
            `uses` int NOT NULL,
            `resolves` int NOT NULL,
            `ratio` float NOT NULL
            )'''

        self.sqlite3cursor.execute(query1)
        self.sqlite3cursor.execute(query2)
        self.sqlite3cursor.execute(query3)
        self.sqlite3connection.commit()

    def import_from_mysql(self):

        logger.info('importing from mysql hashes_to_resolve')
        query = 'select id, infohash from hashes_to_resolve'
        self.mysql_cursor.execute(query)
        rows = self.mysql_cursor.fetchall()
        query = 'delete from hashes_to_resolve'
        self.sqlite3cursor.execute(query)
        query = 'insert into hashes_to_resolve values (?, ?)'
        self.sqlite3cursor.executemany(query, rows)

        logger.info('importing from mysql old_hashes_to_resolve')
        query = 'select id, infohash, runtime from old_hashes_to_resolve'
        self.mysql_cursor.execute(query)
        rows = self.mysql_cursor.fetchall()
        query = 'delete from old_hashes_to_resolve'
        self.sqlite3cursor.execute(query)
        query = 'insert into old_hashes_to_resolve values (?, ?, ?)'
        self.sqlite3cursor.executemany(query, rows)

        logger.info('importing from mysql trackers')
        query = 'select id, url, uses, resolves, ratio from trackers'
        self.mysql_cursor.execute(query)
        rows = self.mysql_cursor.fetchall()
        query = 'delete from trackers'
        self.sqlite3cursor.execute(query)
        query = 'insert into trackers values (?, ?, ?, ?, ?)'
        self.sqlite3cursor.executemany(query, rows)

        self.sqlite3connection.commit()
        sys.exit(0)

    def get_trackers(self):
        self.trackers.load_from_db(self.sqlite3cursor, self.protocols)

    def save_trackers(self):
        self.trackers.save_to_db(self.sqlite3cursor)
        self.sqlite3connection.commit()

    def get_new_jobs(self) -> int:  # number of new jobs
        logger.debug('loading new jobs')
        query = 'select id, infohash from hashes_to_resolve '\
                'order by id '\
                'limit ?'

        self.sqlite3cursor.execute(query, (args.maxnew,))
        rows = self.sqlite3cursor.fetchall()
        for row in rows:
            self.hashes_to_resolve.append([row[0], row[1], 0, 0])
        self.count.increase('new', len(rows))
        return

    def get_old_jobs(self) -> int:
        logger.debug('Loading old jobs')
        query = 'select id, infohash, runtime from old_hashes_to_resolve '\
                'order by runtime asc '\
                'limit ?'
        self.sqlite3cursor.execute(query, (args.maxold,))
        rows = self.sqlite3cursor.fetchall()
        for row in rows:
            self.hashes_to_resolve.append([row[0], row[1], row[2], 0])
        self.count.increase('old', len(rows))
        return

    def sort_jobs(self):
        pass
        # sorting actually done in select preparing hashes in db
        #logger.warning("Sorting not implemented yet")

    def spawn_a_job(self):
        logger.debug('spawning a job')
        job = Job()
        job.id, job.hexhash, job.total_runtime, job.session_runtime = \
            self.hashes_to_resolve.pop(0)
        self.lt_params.info_hash = libtorrent.sha1_hash(
            binascii.a2b_hex(job.hexhash))
        self.lt_params.name = "name_" + job.hexhash
        self.lt_params.trackers = self.trackers.get_random_url(3)
        job.handle = self.lt_session.add_torrent(self.lt_params)

        job.handle.resume()
        self.jobs.append(job)
        _cur_trackers = job.handle.trackers()
        self.last_job_spawn = time.time()

        logger.debug('hashes %s, running %s, sleeping %s',
                     len(self.hashes_to_resolve), len(self.jobs), len(self.timeout_jobs))

    def can_spawn_job(self) -> bool:
        tmp_bool = True
        if self.sessions_throttle:
            tmp_bool = tmp_bool and time.time() > \
                self.last_job_spawn + args.spawn * \
                (1 + len(self.jobs)/self.sessions_throttle)
        else:
            tmp_bool = tmp_bool and time.time() > self.last_job_spawn + args.spawn
        tmp_bool = tmp_bool and (self.hashes_to_resolve or self.timeout_jobs)
        tmp_bool = tmp_bool and len(self.jobs) < args.threads
        return tmp_bool

    def end_a_job(self, job):
        logger.debug('Removing a job completely')
        job.just_die(self.lt_session)

        if job.total_runtime == 0:  # a new hash
            query = 'delete from hashes_to_resolve '\
                    'where id = (?) and infohash = (?) '
        else:
            query = 'delete from old_hashes_to_resolve '\
                    'where id = (?) and infohash = (?) '

        self.sqlite3cursor.execute(query, (job.id, job.hexhash))
        self.sqlite3connection.commit()
        self.jobs.remove(job)

    def enqueue_a_job(self, job: Job):
        logger.debug('timed out job -> back to queueto the end of queue')
        job.go_to_sleep()
        self.jobs.remove(job)
        self.timeout_jobs.append(job)

    def wake_a_job(self):
        logger.debug('Waking up a timed out(previously) job')
        job = self.timeout_jobs.pop(0)
        job.wake_up()
        self.jobs.append(job)
        logger.debug('hashes %s, running %s, sleeping %s',
                     len(self.hashes_to_resolve), len(self.jobs), len(self.timeout_jobs))
        self.last_job_spawn = time.time()

    def purge_a_job(self, job: Job):
        logger.warning('purging a job: %s', job.hexhash)
        job.just_die(self.lt_session)
        self.jobs.remove(job)

    def offload_aged_job(self, job: Job):
        logger.debug('offloading aged job to db')
        job.just_die(self.lt_session)
        if job.total_runtime == 0:  # It was a new hash
            query = 'delete from hashes_to_resolve '\
                    'where id = (?) and infohash like (?) '
            self.sqlite3cursor.execute(query, (job.id, job.hexhash))

            query = 'insert into old_hashes_to_resolve '\
                    '(id, infohash, runtime) '\
                    'values (?, ?, ?)'
            self.sqlite3cursor.execute(
                query, (job.id, job.hexhash, job.session_runtime))

        else:  # it was an old hash
            job.total_runtime += job.session_runtime
            query = 'update old_hashes_to_resolve '\
                    'set runtime = (?) '\
                    'where id = (?) and infohash like (?) '
            self.sqlite3cursor.execute(
                query, (job.total_runtime, job.id, job.hexhash))

        self.sqlite3connection.commit()
        self.jobs.remove(job)
        self.count.increase('offloaded', 1)

    def push_resolved_hash_to_db(self, output):
        assert False
        query = 'insert into resolved_hashes '\
                '(id, infohash, name, peers, seeds, last_seen_complete, num_files) '\
                'values (?, ?, ?, ?, ?, ?, ?) '
        data_row = (output['id'],
                    output['hexhash'],
                    output['name'],
                    output['peers'],
                    output['seeds'],
                    output['last_seen_complete'],
                    output['num_files']
                    )
        self.sqlite3cursor.execute(query, data_row)
        self.sqlite3connection.commit()
        if output['num_files'] > 1:
            query = 'insert into resolved_files (name, size, parenttorrentid) '\
                    'values (?, ?, ?) '
            for file in output['file_list']:
                self.sqlite3cursor.execute(
                    query, (file[0], file[1], output['id']))
        self.sqlite3connection.commit()
        self.count.increase('resolved', 1)

    def keyboard_event(self, key):
        print('-')
        print(f'>{key}< {type(key)}')
        print()
        print('-')

        print('new %s, old %s, resolved %s, offloaded %s',
              self.count.value_of('new'), self.count.value_of('old'),
              self.count.value_of('resolved'), self.count.value_of('offloaded'))
        print('trackers %s, hashes %s, running %s, sleeping %s',
              self.trackers.num,
              len(self.hashes_to_resolve), len(self.jobs), len(self.timeout_jobs))
        print('-')
        if key == 'q':
            self.terminate_resolver(key)

    def terminate_resolver(self, key):
        print('-')
        print('attempting terminate')
        print('-')
        args.heartbeat = 0
        args.maxnew = 0
        args.maxold = 0
        args.threads = 0
        args.aged = 0

    def print_stats_inline(self):
        print('new {}, old {}, resolved {}, queue {}, active {}, sleep {}, offloaded {}    \r'
              .format(self.count.value_of('new'), self.count.value_of('old'),
                      self.count.value_of('resolved'), len(
                          self.hashes_to_resolve),
                      len(self.jobs), len(
                          self.timeout_jobs), self.count.value_of('offloaded')
                      ), end='')

    def run_loop(self):
        """ Main part of program, once initialized runs indefinitely
            or until jobs are done (unlikely)
        """

        while self.jobs or self.hashes_to_resolve or self.timeout_jobs:
            if self.can_spawn_job():
                if self.hashes_to_resolve:
                    self.spawn_a_job()
                else:
                    self.wake_a_job()

            count = 0
            for job in reversed(self.jobs):
                if self.can_spawn_job():
                    if self.hashes_to_resolve:
                        self.spawn_a_job()
                    else:
                        self.wake_a_job()

                time.sleep(args.heartbeat)

                count += 1
                if job.is_complete():
                    #output = job.reap_data()
                    # self.push_resolved_hash_to_db(output)

                    a_torrent = my_torrent_stuff.Torrent()
                    a_torrent.torfile = job.reap_torrent_file()
                    if a_torrent.torfile:
                        a_torrent.digest_torfile()
                        if a_torrent.fl_hexhash.lower() != job.hexhash.lower():
                            logger.critical('job      %s', job.hexhash)
                            logger.critical(
                                'resolved %s', a_torrent.fl_hexhash)
                            self.purge_a_job(job)
                            continue

                        # a_torrent.get_db_info(
                        #     self.sqlite3cursor, dbtype='sqlite')
                        # try:
                        #     a_torrent.update_db(
                        #         self.sqlite3cursor, dbtype='sqlite')
                        # except (AttributeError) as err:
                        #     logger.critical(
                        #         'Update failed for %s', job.hexhash)
                        #     logger.critical('ERR:%s', err)

                        if args.torrents_dir:
                            try:
                                a_torrent.save_file_to(args.torrents_dir)
                            except UnicodeDecodeError as err:
                                print()
                                logger.critical('Decode err: %s', err)
                                logger.critical(
                                    'saving as: %s', a_torrent.fl_hexhash)
                                a_torrent.save_file_to(
                                    args.torrents_dir, filename=a_torrent.fl_hexhash)

                        self.trackers.report_success(job)
                        self.end_a_job(job)
                        self.count.increase('resolved', 1)
                        logger.debug('Saved resolved job')
                    else:
                        logger.error('failed to reap torrent file')
                        print()
                        print(job.hexhash)
                        print()
                        print(job)
                        print()
                        self.purge_a_job(job)
                        print()

                elif job.is_aged():
                    self.trackers.report_failure(job)
                    self.offload_aged_job(job)

                elif job.is_timeout():
                    self.enqueue_a_job(job)

                self.print_stats_inline()
                if args.maxnew == 0 and len(self.jobs) == 0:
                    print('\n\n')
                    sys.exit(0)
            self.print_stats_inline()


def main():
    resolver = Resolver()
    while True:
        resolver.get_trackers()
        resolver.get_new_jobs()
        resolver.get_old_jobs()
        resolver.sort_jobs()
        resolver.run_loop()
        logger.info('Cycle complete, trying to get new jobs')
        resolver.save_trackers()
        old_resolver = resolver
        old_resolver.lt_session.pause()
        resolver = Resolver()
        resolver.count = old_resolver.count
        time.sleep(3)
        del old_resolver


if __name__ == "__main__":
    import logging
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    # fh = logging.FileHandler(__name__ + '.txt')
    # fh.setLevel(logging.DEBUG)
    # fh.setFormatter(formatter)
    sh = logging.StreamHandler()
    sh.setLevel(logging.INFO)
    sh.setFormatter(formatter)

    # logger.addHandler(fh)
    logger.addHandler(sh)

    from argparse import ArgumentParser
    parser = ArgumentParser(
        description='Unknown/incomplete info hash resolver')
    parser.add_argument('-idb', dest='main_import', default=False, action='store_true',
                        help='import hashes from main db')
    parser.add_argument('-itxt', dest='text_import', default='', type=str,
                        help='import from text file')

    parser.add_argument('-d', '-dir', dest='torrents_dir', default='_resolver', type=str,
                        help='directory to save torrent files, default _resolver')
    parser.add_argument('-timeout', dest='timeout', default=99999, type=int,
                        help='timeout in seconds for single try of hash')
    parser.add_argument('-aged', dest='aged', default=7200, type=int,
                        help='timeout in seconds before offload back to db')
    parser.add_argument('-threads', dest='threads', default=99999, type=int,
                        help='maximum concurrent hashes')
    parser.add_argument('-spawntime', dest='spawn', default=700, type=int,
                        help='min time between torrent spawns in miliseconds')
    parser.add_argument('-maxnew', dest='maxnew', default=99999, type=int,
                        help='maximum new hashes at once')
    parser.add_argument('-maxold', dest='maxold', default=99999, type=int,
                        help='maximum old hashes at once')

    parser.add_argument('-hb', '--heartbeat', dest='heartbeat', default=20, type=int,
                        help='sleep time between actions')

    parser.add_argument('--version', action='version', version=VERSION)
    args = parser.parse_args()
    args.spawn = args.spawn / 1000
    args.heartbeat = args.heartbeat / 1000

    print = functools.partial(print, flush=True)
    main()
