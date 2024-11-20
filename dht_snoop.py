#!./bin/python3

import functools
import os
import sys
import time
import binascii
from typing import List, Set
import random
import tempfile
import sqlite3
import mysql.connector
import libtorrent
import my_torrent_stuff
from connect_qb import connect_qb

VERSION = "0.0.1"


class Counter:
    def __init__(self) -> None:
        self.names = ['jobs', 'new', 'old', 'resolved', 'offloaded', 'ticker', 'added_to_qb', 'added_to_qb_clone', 'scraped', 'scraped_new']
        self.values = {}
        for name in self.names:
            self.values[name] = 0
            setattr(self, name, 0)

    def increase(self, what: str, value: int =1):
        self.values[what] += value
        setattr(self, what, getattr(self, what) + value)

    def value_of(self, what: str) -> int:
        return self.values[what]

    def tick(self):
        animation = '-\|/'
        self.ticker = (self.ticker+1) % (len(animation) *4)
        return animation[int(self.ticker /4)]

class Job:
    def __init__(self):
        self.handle = None
        self.total_runtime = 0
        self.session_runtime = 0
        self.hexhash: str
        self.action: str = None
        self.priority :int = 0
        self.trackers = []

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
        for tracker in self.trackers:
            tracker['resolves']+=1
        output = {}
        logger.debug('reaping completed job')
        status = self.handle.status()
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
                {'url': row.strip('\n'), 'uses': 0, 'resolves': 1, 'ratio': 0})
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
                {'url': row[0], 'uses': row[1], 'resolves': 1, 'ratio': row[3]})
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

    def get_random(self, amount:int) -> Set:
        return set()
        resolves_total = 0
        count = 0
        for tracker in self.list:
            count+=1
            resolves_total += tracker['resolves']
        print(f'\n{resolves_total} of {count}')
        
        random_trackers = set()
        while len(random_trackers) < amount:
            a_number = random.randint(0,resolves_total)
            count = 0
            for tracker in self.list:
                count += tracker['resolves']
                if count >= a_number:
                    random_trackers.add(tracker)
                    break
        return random_trackers

    def get_random_url(self, amount: int) -> List:
        assert False
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
        self.new_hashes = set()
        self.known_hashes = set()
        self.ignore_alerts = set()
        self.is_sniffing = False
        self.last_job_spawn = 0
        self.active_jobs: List[Job] = []
        # self.timeout_jobs: List[Job]
        # self.timeout_jobs = []
        self.trackers = Trackers()
        self.jobs_to_resolve: List[Job] = []
        self.count = Counter()
        logger.debug('connecting to db')
        mysql_database_name = "tpb"
        # mysql_user = os.environ.get("mysql_user")
        # mysql_password = os.environ.get("mysql_password")
        # mysql_host = os.environ.get("mysql_host")
        mysql_user = 'some_user'
        mysql_password = 'some_user_password'
        mysql_host = '192.168.2.205'

        self.mysql_cursor = False
        self.mysql_connection = False
#        keyboard.on_press(self.keyboard_event)
#        keyboard.on_press_key('q', self.terminate_resolver)

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
            input('import done')
            sys.exit(0)            


        if args.text_import:
            self.import_from_file(args.text_import, action='add_to_qb')
            input('import done')
            sys.exit(0)

        if args.text_import_clones:
            self.import_from_file(args.text_import_clones, action='add_to_qb_clone')
            input('import done')
            sys.exit(0)

        if args.text_remove:
            self.remove_from_file(args.text_remove)
            input('remove done')
            sys.exit(0)


        logger.debug('initializing libtorrent session')
        self.protocols = ['udp', 'tcp']
        self.session_settings = libtorrent.default_settings()
        self.session_settings['listen_interfaces'] = '0.0.0.0:6818'
        self.session_settings['peer_fingerprint'] = 'non-default-finger-print'
        self.session_settings['announce_to_all_trackers'] = False  # False
        self.session_settings['validate_https_trackers'] = False  # true
        self.session_settings['tracker_completion_timeout'] = 30  # 30
        self.session_settings['connection_speed'] = 10  # 30
        self.session_settings['connections_limit'] = 500  # 200
        self.session_settings['listen_queue_size'] = 5  # 5
        self.session_settings['torrent_connect_boost'] = 3  # 30
        self.session_settings['max_concurrent_http_announces'] = 50  # 50
        self.session_settings['enable_upnp'] = False #true
        self.session_settings['enable_lsd'] = False #true
        
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
            `infohash` char(40) PRIMARY KEY,
            'action' varchar(40) DEFAULT NULL,
            `runtime` integer NOT NULL DEFAULT '0'
            )  '''

        query3 = '''
            CREATE TABLE IF NOT EXISTS `trackers` (
            `id` integer PRIMARY KEY,
            `url` char(250) UNIQUE,
            `uses` int NOT NULL,
            `resolves` int NOT NULL,
            `ratio` float NOT NULL
            )'''

        query4 = '''
            CREATE TABLE IF NOT EXISTS `resolved_hashes` (
            `infohash` char(40) PRIMARY KEY,
            'action' varchar(40) DEFAULT NULL,
            `runtime` integer NOT NULL 
            )  '''


        self.sqlite3cursor.execute(query1)
        self.sqlite3cursor.execute(query3)
        self.sqlite3cursor.execute(query4)
        self.sqlite3connection.commit()

    def import_from_file(self, file, action=''):
        count = 0
        query = 'insert or ignore into hashes_to_resolve (infohash, action) values (?, ?)'

        with open(file, 'r') as fc:
            while row:= fc.readline().lower():
                if row.endswith('\n'):
                    row=row[:-1]
                if len(row)<40:
                    continue                    
                print(len(row), end = ' ')
                print(f'{row}', end = '')
                self.sqlite3cursor.execute(query, (row, action))
                count+=1
                print(f' total {count} hashes')                
            self.sqlite3connection.commit()
            print()

    def remove_from_file(self, file):
        count = 0
        query = 'delete from hashes_to_resolve where infohash like ?'

        with open(file, 'r') as fc:
            while row:= fc.readline().lower():
                if row.endswith('\n'):
                    row=row[:-1]
                if len(row)<40:
                    continue                    
                print(len(row), end = ' ')
                print(f'{row}', end = '')
                self.sqlite3cursor.execute(query, (row, ))
                count+=1
                print(f' total {count} hashes')                
            self.sqlite3connection.commit()
            print()

    def import_from_mysql(self):
        # temporarily non functional
        logger.info('importing from mysql hashes_to_resolve')
        query = 'select infohash from torrents where id not in (select parenttorrentid from files)'
        self.mysql_cursor.execute(query)
        rows = self.mysql_cursor.fetchall()
        count = 0
        count_total = len(rows)
        query = 'insert or ignore into hashes_to_resolve (infohash, action) values (?, ?)'
        action = ''
        for row in rows:
            count+=1
            infohash = row[0].lower()
            print(f'\r{count} of {count_total} ', end='')
            self.sqlite3cursor.execute(query, (infohash, action))
        self.sqlite3connection.commit()
        print()

    def get_trackers(self):
        self.trackers.load_from_db(self.sqlite3cursor, self.protocols)

    def save_trackers(self):
        self.trackers.save_to_db(self.sqlite3cursor)
        self.sqlite3connection.commit()

    def load_jobs(self) -> int : #number of loaded jobs
        logger.debug('Loading some jobs')
        query = 'select infohash, action, runtime from hashes_to_resolve '\
                'order by runtime asc '

        self.sqlite3cursor.execute(query)
        rows = self.sqlite3cursor.fetchall()
        for row in rows:
            a_job = Job()
            a_job.hexhash = row[0]
            a_job.action = row[1]
            a_job.total_runtime = row[2]
            a_job.priority = a_job.total_runtime if not args.nornd else int((a_job.total_runtime+60)*random.random())
            self.jobs_to_resolve.append(a_job)

        self.count.jobs = len(rows)
        self.sort_jobs()
        return len(rows)
    
    def create_job(self, hex_hash:str, action:str):
        a_job = Job()
        a_job.hexhash = hex_hash
        a_job.action = action
        a_job.total_runtime = 0
        a_job.priority = 0
        self.jobs_to_resolve.insert(0, a_job)

    def sort_jobs(self):
        self.jobs_to_resolve.sort(key=lambda x: x.priority)

    def spawn_a_job(self):
        logger.debug('spawning a job')
        job = self.jobs_to_resolve.pop(0)

#        print(len(job.hexhash), f'>{job.hexhash}<')
        self.lt_params.info_hash = libtorrent.sha1_hash(
            binascii.a2b_hex(job.hexhash))
        self.lt_params.name = "name_" + job.hexhash
        job.trackers = self.trackers.get_random(1)
        urls = []
        for tracker in job.trackers:
            tracker['uses'] +=1
            urls.append(tracker['url'])
        self.lt_params.trackers = urls
        job.handle = self.lt_session.add_torrent(self.lt_params)

        job.handle.resume()
        self.active_jobs.append(job)
        _cur_trackers = job.handle.trackers()
        self.last_job_spawn = time.time()

        logger.debug('hashes %s, running %s', 
                     len(self.jobs_to_resolve), len(self.active_jobs))

    def can_spawn_job(self) -> bool:
        tmp_bool = True
        if self.sessions_throttle:
            tmp_bool = tmp_bool and time.time() > \
                self.last_job_spawn + args.spawn * \
                (1 + len(self.active_jobs)/self.sessions_throttle)
        else:
            tmp_bool = tmp_bool and time.time() > self.last_job_spawn + args.spawn
        tmp_bool = tmp_bool and self.jobs_to_resolve 
        tmp_bool = tmp_bool and len(self.active_jobs) < args.threads
        return tmp_bool

    def end_a_job(self, job:Job):
        logger.debug('Removing a job completely')
        job.just_die(self.lt_session)

        query = 'insert or ignore into resolved_hashes select * from hashes_to_resolve where infohash = (?)'
        self.sqlite3cursor.execute(query, (job.hexhash,))
        
        query = 'delete from hashes_to_resolve where infohash = (?) '
        self.sqlite3cursor.execute(query, (job.hexhash,))
        
        # query = 'insert or ignore into resolved_hashes '\
        #         '(infohash, runtime) '\
        #         'values (?, ?)'        
        # self.sqlite3cursor.execute(query, (job.hexhash, job.total_runtime+job.session_runtime))
        
        self.sqlite3connection.commit()
        self.active_jobs.remove(job)

    def purge_a_job(self, job: Job):
        logger.warning('purging a job: %s', job.hexhash)
        job.just_die(self.lt_session)
        self.active_jobs.remove(job)

    def offload_aged_job(self, job: Job):
        logger.debug('offloading aged job to db')
        job.just_die(self.lt_session)

        job.total_runtime += job.session_runtime
        query = 'update hashes_to_resolve '\
                'set runtime = (?) where '\
                'infohash = (?) '
        self.sqlite3cursor.execute(query, (job.total_runtime, job.hexhash))

        self.sqlite3connection.commit()
        self.active_jobs.remove(job)
        self.count.increase('offloaded')

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
        msg = f'Total {self.count.jobs} '
        msg+= f'queued {len(self.jobs_to_resolve)} '
        msg+= f'resolved {self.count.resolved} '
        msg+= f'scraped/new {self.count.scraped}/{self.count.scraped_new} '
        msg+= f'active {len(self.active_jobs)} '
        msg+= f'added_to_qb {self.count.added_to_qb} '
        msg+= f'offloaded {self.count.offloaded} '
        msg+= f'{self.count.tick()} '
        print(msg, end = '   \r')

    def run_loop(self):
        """ Main part of program, once initialized runs indefinitely
            or until jobs are done (unlikely)
        """

        while True: #self.active_jobs or self.jobs_to_resolve :
            if self.can_spawn_job():
                if self.jobs_to_resolve:
                    self.spawn_a_job()

            count = 0
            for job in reversed(self.active_jobs):
                if self.can_spawn_job():
                    if self.jobs_to_resolve:
                        self.spawn_a_job()

                self.handle_sniffer()
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

                        if args.scrape_dir and job.action == 'save_scrape':
                            try:
                                a_torrent.save_file_to(args.scrape_dir)
                            except UnicodeDecodeError as err:
                                print()
                                logger.critical('Decode err: %s', err)
                                logger.critical(
                                    'saving as: %s', a_torrent.fl_hexhash)
                                a_torrent.save_file_to(
                                    args.scrape_dir, filename=a_torrent.fl_hexhash)

                        if args.torrents_dir and job.action != 'save_scrape':
                            try:
                                a_torrent.save_file_to(args.torrents_dir)
                            except UnicodeDecodeError as err:
                                print()
                                logger.critical('Decode err: %s', err)
                                logger.critical(
                                    'saving as: %s', a_torrent.fl_hexhash)
                                a_torrent.save_file_to(
                                    args.torrents_dir, filename=a_torrent.fl_hexhash)

                        if job.action == 'add_to_qb':
                            result = a_torrent.add_self_to_local_qbittorrent(category='_resolver', tag='_rsv')
                            if result:
                                self.count.increase('added_to_qb')
                            else:
                                print('FAIL')
                                input()
                                sys.exit(0)
            
                        if job.action == 'add_to_qb_clone':
                            result = a_torrent.add_self_to_local_qbittorrent(category='_clone', tag='_rsv_clone')
                            if result:
                                self.count.increase('added_to_qb_clone')
                            else:
                                print('FAIL')
                                input()
                                sys.exit(0)
                        
                        self.trackers.report_success(job)
                        self.end_a_job(job)
                        self.count.increase('resolved')
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

                # elif job.is_timeout():
                #     self.enqueue_a_job(job)

                #self.print_stats_inline()
                if args.maxnew == 0 and len(self.active_jobs) == 0:
                    print('\n\n')
                    sys.exit(0)
            #self.print_stats_inline()

    def prep_sniffer(self):

        alert_mask = libtorrent.alert.category_t.dht_notification
        alert_mask = 65535
        self.lt_session.set_alert_mask(alert_mask)
        self.is_sniffing = True
        self.ignore_alerts.add('torrent_log_alert')
        self.ignore_alerts.add('peer_log_alert')
        # self.ignore_alerts.add('dht_reply_alert')
        self.ignore_alerts.add('dht_outgoing_get_peers_alert')
        self.ignore_alerts.add('stats_alert')
        self.ignore_alerts.add('peer_disconnected_alert')
        self.ignore_alerts.add('peer_connect_alert')
        self.ignore_alerts.add('incoming_connection_alert')
        self.ignore_alerts.add('dht_get_peers_alert')
        #self.ignore_alerts.add('')
        #self.ignore_alerts.add('')

    def handle_sniffer(self):
        if not self.is_sniffing:
            return
        alerts = self.lt_session.pop_alerts()
        for alert in alerts:
            self.handle_alert(alert)

    def handle_alert(self, alert):
        alert_type = type(alert).__name__
        if alert_type in self.ignore_alerts:
            return


        print(f'\n{alert_type}, {alert.message()}')

        if alert_type != 'dht_announce_alert':
#            print(f'\n{alert_type}, {alert.message()}')
            return

        try:
            byte_hash = alert.info_hash.to_string()
            port = alert.port
            ip = alert.ip
        except Exception as err:
            print(err)
            return

        if byte_hash not in self.known_hashes:            
            self.known_hashes.add(byte_hash)
            
            print(f'New hash {byte_hash.hex().lower()} {ip}:{port}')
            self.count.increase('scraped')
            if self.is_scraped_hash_new(byte_hash):
                self.count.increase('scraped_new')
                self.put_new_hash_to_db(byte_hash)
                self.add_scraped_hash_to_resolver(byte_hash)
            # else:
                # print('But not really new')

    def add_scraped_hash_to_resolver(self, byte_hash):
        query = 'insert or ignore into hashes_to_resolve (infohash, action) values (?, ?)'
        hex_hash = byte_hash.hex().lower()
        self.sqlite3cursor.execute(query, (hex_hash, 'save_scrape'))
        self.sqlite3connection.commit()
        self.create_job(hex_hash, 'save_scrape')

    def is_scraped_hash_new(self, byte_hash) -> bool:
        query = 'select byte_hash from known_hashes where byte_hash = ?'
        self.sqlite3cursor.execute(query, (byte_hash,))
        rows = self.sqlite3cursor.fetchall()
        if rows:
            return False
        return True

    def put_new_hash_to_db(self, byte_hash):
        query = 'insert into known_hashes (byte_hash) values (?)' 
        self.sqlite3cursor.execute(query, (byte_hash, ))
        hex_hash = byte_hash.hex().lower()
        query = 'insert into scraped_hashes (hex_hash) values (?)'
        self.sqlite3cursor.execute(query, (hex_hash, ))
        self.sqlite3connection.commit()

def main():
    resolver = Resolver()
    resolver.prep_sniffer()
    while True:
        resolver.get_trackers()
        #resolver.load_jobs()
    
        a_job = Job()
        a_job.hexhash = 'bed4cca28e993f12fe92324b2dc4cb20269e0aab'
        a_job.hexhash = '1111111111111111111111111111111111111111'
        a_job.action = ''
        a_job.total_runtime = 0
        a_job.priority = 0
        resolver.jobs_to_resolve.append(a_job)        
        
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
    parser.add_argument('-idb_just_resolve', dest='main_import', default=False, action='store_true',
                        help='import hashes from main db')
    parser.add_argument('-addtxt', dest='text_import', default='', type=str,
                        help='import from text file')

    parser.add_argument('-addclones', dest='text_import_clones', default='', type=str,
                        help='import from text file as possible clones')

    parser.add_argument('-rmtxt', dest='text_remove', default='', type=str,
                        help='import from text file')

    parser.add_argument('-savedir', dest='torrents_dir', default='_resolver', type=str,
                        help='directory to save torrent files, default _resolver')

    parser.add_argument('-scrapedir', dest='scrape_dir', default='_scrape', type=str,
                        help='directory to save scraped torrent files, default _scrape')

    # parser.add_argument('-timeout', dest='timeout', default=99999, type=int,
    #                     help='timeout in seconds for single try of hash')

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
    parser.add_argument('-nornd', action='store_true', help='disable randomness')

    parser.add_argument('-hb', '--heartbeat', dest='heartbeat', default=20, type=int,
                        help='sleep time between actions')

    parser.add_argument('--version', action='version', version=VERSION)
    args = parser.parse_args()
    args.spawn = args.spawn / 1000
    args.heartbeat = args.heartbeat / 1000

    print = functools.partial(print, flush=True)
    main()
