
The core idea of these tools is, that when we have an incomplete torrent, we can hash arbitrary file or other torrent's partial .qB! files while applying metadata from the needy torrent, we can potentially find usefull data and inject it into the incomplete torrent.

qbt_deduper - Will look for data in locally available files. It can incorporate found data or remove file from within torrent if a complete copy is found.

qbt_hammer - Will look for data in other torrents being downloaded, can exchange available data between those torrents (safe, but duplicates data on disk) or consolidate the data into a single file, and point both torrent's to the same file (unsafe and when one torrent completes, the other torrent(s) get the file 'stolen' from them, requires qbt_deduper to fix, as it will find completed file, and therefore it can remove it from other torrents using the same file). This very feature could use rework for file systems which support reflinks.

With additional script that looks for same-sized files in a torrent database, this allows using qbt_hammer to seek data far beyond local files and torrent client.

The rework of this code is pending.

