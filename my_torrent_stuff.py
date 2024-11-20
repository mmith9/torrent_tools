#!/usr/bin/env python -u
# pylint: disable=missing-module-docstring
# pylint: disable=missing-class-docstring
# pylint: disable=missing-function-docstring
import logging
import sys
import os
import hashlib
import datetime
import bencode
from connect_qb import connect_qb

logger = logging.getLogger(__name__)
logger.setLevel(logging.WARN)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
fh = logging.FileHandler(__name__ + '.txt')
fh.setLevel(logging.DEBUG)
fh.setFormatter(formatter)
sh = logging.StreamHandler()
sh.setLevel(logging.DEBUG)
sh.setFormatter(formatter)
# logger.addHandler(fh)
logger.addHandler(sh)


TESTLEVEL = 0


class Torrent:

    def __init__(self):
        self.torinfo: dict
        self.info: dict
        self.torfile = b''

        self.fl_name: str
        self.fl_size: int
        self.fl_hexhash: str
        self.fl_filelist = []

        self.db_name: str
        self.db_truename: str
        self.db_added_date: int
        self.db_size: int
        self.db_hexhash: str
        self.db_files = []
        self.db_file_rows: int
        self.db_numfiles: int
        self.db_id: int

    def add_self_to_local_qbittorrent(self, category='', tag='') -> bool:
        try:
            # print()
            # print('connecting')
            qbt_client = connect_qb('192.168.2.206')
            # print('connected')

            result = qbt_client.torrents_add(torrent_files=self.torfile, \
                category=category, \
                is_paused=True, \
                use_auto_torrent_management=True, \
                is_sequential_download=True, \
                is_first_last_piece_priority=True,\
                tags=['fresh', tag], 
                )
            
            return True            
        except Exception as err:
            print('Failed to add torrent to qbt')
            print(self.fl_hexhash)
            print(err)
            return False

    def save_file_to(self, dest_dir, filename='') -> str:
        if not filename:
            torinfo = bencode.bdecode(self.torfile)
            filename = torinfo['info']['name']

            if len(filename)>255:
                print('\nTruncating long filename')
                print(filename)
                if filename.endswith('.torrent'):
                    filename = filename[:-len('.torrent')]

                while len(filename) + len('.torrent') > 255:
                    filename = filename[:-1]
                filename = filename + '.torrent'
                print(filename)

        if isinstance(filename, bytes) or isinstance(dest_dir, bytes):
            if isinstance(dest_dir, str):
                dest_dir = bytes(dest_dir, 'utf-8')
            if isinstance(filename, str):
                filename = bytes(filename, 'utf-8')
            for bad_char in bytes('*?\\/\";:|,\'<>', 'utf-8'):
                filename = filename.replace(bytes(str(bad_char), 'utf-8'), bytes('!', 'utf-8'))
            filename += bytes('.torrent', 'utf-8')
        else:
            for bad_char in '*?\\/\";:|,\'<>':
                filename = filename.replace(bad_char, '!')
            filename += '.torrent'

        if not os.path.exists(dest_dir):
            os.makedirs(dest_dir)
        final_file_path = os.path.join(dest_dir, filename)
        try:
            file_h = open(final_file_path, 'wb')
            file_h.write(self.torfile)
            file_h.close()
            return final_file_path
        except Exception as err:
            print('Torrent file cant be saved')
            print(final_file_path)
            print('because of')
            print(err)
            print()
            if isinstance(dest_dir, bytes):
                final_file_path = os.path.join(dest_dir, bytes(self.fl_hexhash + '_error.torrent', 'utf-8'))
            else:
                final_file_path = os.path.join(dest_dir, self.fl_hexhash + '_error.torrent')
            print('using name')
            print(final_file_path)
            print()
            file_h = open(final_file_path, 'wb')
            file_h.write(self.torfile)
            file_h.close()
            return final_file_path

    def load_torrent_file_info(self, file_name: str):
        try:
            file = open(file_name, "rb")
            self.filename = file_name
            self.torfile = file.read()
            file.close()
            
        except Exception:
            logger.error('Failed to load file %s', file_name)
            return False
        if not self.digest_torfile():
            logger.warn('Failed to digest torfile %s', file_name)
            return False
        
        return True

    def digest_torfile(self):
        try:
            self.torinfo = bencode.bdecode(self.torfile)
        except Exception as err:
#            logger.critical('Failed to de-ben-code %s', self.filename)
            logger.error('debencode fail: %s',err)
            return False
        try:
            self.info = self.torinfo['info']
            self.fl_name = self.info['name']
        except (KeyError, TypeError) as err:
#            logger.critical('error processing file %s', self.filename)
            logger.critical('encountered error %s', err)
            return False

        if isinstance(self.fl_name, (bytes, bytearray)):
            try:
                self.fl_name = self.fl_name.decode("utf-8")
            except UnicodeDecodeError:
                logger.warning('utf-8 decode error on %s', self.fl_name)
                self.fl_name = "utf-8 decode error"
                

        try:
            if 'files' in self.info:        # yield pieces from a multi-file torrent
                self.fl_filelist = self.info['files']
                self.fl_size = 0
                for file in self.info['files']:
                    self.fl_size += file['length']
            else:                           # yield pieces from a single file torrent
                self.fl_filelist = [
                    {"length": self.info['length'], "path":[self.info['name']]}]
                self.fl_size = self.info['length']
        except (KeyError, TypeError) as err:
            logger.critical('error processing file %s', self.filename)
            logger.critical('encountered error %s', err)
            return False

        self.fl_hexhash = hashlib.sha1(bencode.bencode(self.info)).hexdigest()
        return True

    def print_file_info(self, print_files=False):

        print("torrent file hash", self.fl_hexhash)
        print("torrent true name", self.fl_name)
        print("files in torrent", len(self.fl_filelist))
        print("torrent size", self.fl_size)

        if print_files:
            for file in self.fl_filelist:
                print(file['length'], file['path'])

    # returns number of hash matches, always should be 1 or 0
    def get_db_info(self, cursor, dbtype="sqlite3") -> int:

        assert isinstance(self.fl_hexhash, str)
        assert len(self.fl_hexhash) == 40

        if dbtype == "sqlite3":
            query = "select name, infohash, numfiles, size, added, truename, id "\
                    "from torrents "\
                    "where infohash like (?)"
        elif dbtype == "mysql":
            query = "select name, infohash, numfiles, size, added, truename, id "\
                    "from torrents "\
                    "where infohash like (%s)"
        else:
            assert False

        if TESTLEVEL > 70:
            print(query)
            print("args:", (self.fl_hexhash))
        cursor.execute(query, (self.fl_hexhash,))
        rows = cursor.fetchall()
        if rows:
            if len(rows) == 1:
                row = rows[0]
                self.db_name = row[0]
                self.db_hexhash = row[1]
                self.db_numfiles = row[2]
                self.db_size = int(row[3])
                self.db_added_date = row[4]
                self.db_truename = row[5]
                self.db_id = row[6]

                # for x in row:
                #    print(x, type(x))
            else:
                print("Multiple matches!!")
                for row in rows:
                    print(row)
                assert False
                return len(rows)
        else:                                          # no matches in db
            return 0

        if dbtype == "sqlite3":
            query = "select fl.size, fl.name "\
                    "from files fl, torrents tr "\
                    "where fl.parenttorrentid = tr.id and tr.infohash like (?)"
        elif dbtype == "mysql":
            query = "select fl.size, fl.name "\
                    "from files fl, torrents tr "\
                    "where fl.parenttorrentid = tr.id and tr.infohash like (%s)"
        else:
            assert False

        cursor.execute(query, (self.fl_hexhash,))
        rows = cursor.fetchall()
        if rows:
            self.db_file_rows = len(rows)
            self.db_files = rows
        else:
            self.db_file_rows = 0

        return 1

    def print_db_info(self, print_files=False):

        print("torrent db hash", self.db_hexhash)
        print("torrent name", self.db_name)
        print("torrent true name", self.db_truename)
        if self.db_added_date:
            print("added", self.db_added_date,
                  datetime.datetime.fromtimestamp(self.db_added_date))
        else:
            print("added Null")
        print("files in torrent", self.db_numfiles)
        print("files in list", self.db_file_rows)
        print("torrent size", self.fl_size)
        if print_files:
            for file in self.db_files:
                print(file)

    def is_db_info_up_to_date(self) -> bool:
        bhelper = True
        bhelper = bhelper and (self.db_truename == self.fl_name)
        bhelper = bhelper and (len(self.fl_filelist) == self.db_numfiles)
        return bhelper

    def update_db(self, cursor, dbtype="sqlite3") -> None:
        if dbtype == "sqlite3":
            query = "update torrents "\
                    "set truename = ?, numfiles = ?, size = ? "\
                    "where id = ? "
        elif dbtype == "mysql":
            query = "update torrents "\
                    "set truename = %s, numfiles = %s, size = %s "\
                    "where id = %s "
        else:
            assert False

        if TESTLEVEL > 70:
            print(query)
            print("args:", (self.fl_name, len(
                self.fl_filelist), self.fl_size, self.db_id))
        cursor.execute(
            query, (self.fl_name, len(self.fl_filelist), self.fl_size, self.db_id))

        if len(self.fl_filelist) > 1 and len(self.fl_filelist) != self.db_file_rows:
            if dbtype == "sqlite3":
                query = "delete from files "\
                        "where parenttorrentid = ?"
            elif dbtype == "mysql":
                query = "delete from files "\
                        "where parenttorrentid = %s"
            else:
                assert False

            cursor.execute(query, (self.db_id,))

            if dbtype == "sqlite3":
                query = "insert into files (size, name, parenttorrentid) values (?,?,?)"
            elif dbtype == "mysql":
                query = "insert into files (size, name, parenttorrentid) values (%s,%s,%s)"
            else:
                assert False

            for file in self.fl_filelist:
                file_name = ""
                for item in file['path']:
                    try:
                        file_name += item + "/"
                    except TypeError:
                        file_name += "<TypeError>" + "/"

                file_name = file_name[:-1]  # ditch the last /
                cursor.execute(query, (file['length'], file_name, self.db_id))

    def insert_new_torrent_below_threshold(self, cursor, dbtype="sqlite3") -> None:
        if dbtype == "sqlite3":
            query = 'select * from torrents where infohash like ?'
        elif dbtype == "mysql":
            query = 'select * from torrents where infohash like %s'
        else:
            assert False
        cursor.execute(query, (self.fl_hexhash,))
        rows = cursor.fetchall()
        if len(rows) > 0:
            return False

        # all new start with 3.2m index, rest was lost
        query = 'select max(id) from torrents where id<3000000'
        cursor.execute(query)
        rows = cursor.fetchall()
        new_id = rows[0][0] + 1

        if dbtype == "sqlite3":
            query = "insert into torrents (id, infohash) values "\
                    "(?, ?) "\

        elif dbtype == "mysql":
            query = "insert into torrents (id, infohash) values "\
                    "(%s, %s) "
        else:
            assert False

        if TESTLEVEL > 70:
            print(query)

        cursor.execute(query, (new_id, self.fl_hexhash))
        return True

    def is_truename_in_db(self, cursor, dbtype="sqlite3") -> bool:

        if dbtype == "sqlite3":
            query = "select truename from torrents "\
                    "where infohash like (?)"
        elif dbtype == "mysql":
            query = "select truename from torrents "\
                    "where infohash like (%s)"
        else:
            assert False

        cursor.execute(query, (self.fl_hexhash,))
        rows = cursor.fetchall()
        if rows:
            row = rows[0]
            truename_found = self.fl_name == row[0]
        else:
            truename_found = False
        return truename_found

def size_to_dib(size):
    index = 0
    new_size = int(size / 1024)
    while new_size >= 1024:
        new_size = int(new_size / 1024)
        index += 1
    new_size = str(new_size) + [' KiB', ' MiB', ' GiB', ' TiB'][index]
    return new_size
