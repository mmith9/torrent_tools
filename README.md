The core idea of these tools is, that when we have an incomplete torrent, we can hash arbitrary file or other torrent's partial .qB! files while applying metadata from the needy torrent which allows to find usefull data and inject it into the incomplete torrent.

qbt_deduper - Will look for data in locally available files. It can incorporate found data or remove file from within torrent if a complete copy is found.

qbt_hammer - Will look for data in other torrents being downloaded, can exchange available data between those torrents (safe, but duplicates data on disk) or consolidate the data into a single file, and point both torrent's to the same file (unsafe and when one torrent completes, the other torrent(s) get the file 'stolen' from them, requires qbt_deduper to fix, as it will find completed file, and therefore it can remove it from other torrents using the same file). This very feature could use rework for file systems which support reflinks.

The useful data extraction takes two or more torrents, looks which pieces have been downloaded and verified in each, translates that into usable data ranges, and checks if that data can be used to fill gaps in other torrents by testing it against their piece hashes. If no contiguous piece fits, it can take scraps of data available and attempt to recombine them testing all possible combinations of available data against given piece hash.
Theres a cap on the number of combinations, which is known prior to testing. The main safeguard for combinatorical explosion is implemented much earlier, as the explosion causes problems long before looking into single piece ranges. The algorithm, unless told to not, will exclude known problematic files, based on provided regexps, like archives cut into same size pieces, or VOB files from dvd rips that all have same 1GiB size.



The rework of this code is pending.

