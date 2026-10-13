import logging
import logging.config
import time
from enum import Enum, auto
from typing import List

from pydantic.dataclasses import dataclass

logging.config.fileConfig('logging.conf')
logger = logging.getLogger(__name__[__name__.find('.')+1:])
logp = logging.getLogger('print')

logger.debug('importing klasses')

@dataclass
class FileOfSize:
    size: int
    path: str
    parent_hash: str

# @dataclass
# class File:
#     size: int 
#     path_client: str
#     exists: bool = True
#     is_from_qbt: bool = False

#     piece_states: List[int] = []
#     piece_hashes: List[str] = []
#     pieces_offset: int = 0

#                 insert = {'file': file,
#                       'torrent': trr,
#                       'id': file['id'],
#                       'hash': trr.hash,
#                       'file_is_complete': file_is_complete,
#                       'file_exists': file_exists,
#                       'filename': file['name'],
#                       'path_server': file['name'],
#                       'full_path_client': full_path_client,
#                       'is_last_file_in_torrent': (file.size + file_offset == trr.size),
#                       'file_offset': file_offset,
#                       'progress': file['progress'],
#                       'debug': f't{trr.hash[:4]}f{file["id"]}',
#                       'size': file.size,
#                       'piece_size': trr.properties.piece_size,
#                       'pieces_start': pieces_start,
#                       'pieces_end': pieces_end,
#                       'pieces_offset': pieces_offset,
#                       'piece_states': piece_states,
#                       'pieces_updated': [],

#                       'ranges_complete': ranges_completed,
#                       'ranges_updated': II.empty(),
#                       'ranges_needed': II.closedopen(0, filesize) - ranges_completed,

#                       'first_block_shared': (pieces_offset < 0),
#                       'last_block_shared': is_last_block_shared,

#                       }

