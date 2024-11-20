import qbittorrentapi

def connect_qb(ip_address:str):
    # instantiate a Client using the appropriate WebUI configuration
    qbt_client = qbittorrentapi.Client(
        host=ip_address,
        port=8070,
        username='admin',
        password='',
        REQUESTS_ARGS={'timeout': (15.1, 60.6)}
    )

    # the Client will automatically acquire/maintain a logged in state in line with any request.
    # therefore, this is not necessary; however, you many want to test the provided login credentials.
    try:
        qbt_client.auth_log_in()
    except qbittorrentapi.LoginFailed as err:
        print(err)
    return qbt_client
