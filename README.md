Set of tools for advanced management through qBittorrent api

You maybe trying to download a torrent that cannot complete, but:
- there are other torrents with the data but incomplete too
- you may have some of the files allready somewhere locally
- you may have somehow corrupted download folder with incomplete downloads and need to reuse the data

qbt_deduper - Will look for data locally, can use incomplete data and add it to download or remove file from downloads if copy exists locally

qbt_hammer - Will look for data in other torrents being downloaded, can exchange available data between those torrents or consolidate the data and point all downloads towards one destination file

