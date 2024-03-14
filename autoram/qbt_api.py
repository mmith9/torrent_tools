import configparser
import logging.config


import qbittorrentapi

logging.config.fileConfig('logging.conf')
logger = logging.getLogger(__name__)
config = configparser.ConfigParser(allow_no_value=True, delimiters='=')
config.read('autoram.ini')

def connect_qbt():
    qbt_client = qbittorrentapi.Client(
        host=config['server']['host'],
        port=config['server']['port'],
        username=config['server']['username'],
        password=config['server']['password'],
        REQUESTS_ARGS={'timeout': (
            float(config['server']['connect_timeout']),
            float(config['server']['read_timeout'])
            )}
    )

    try:
        qbt_client.auth_log_in()
    except qbittorrentapi.LoginFailed as err:
        print(err)
    return qbt_client
