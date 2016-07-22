#! /bin/sh
mkdir mktorrent
cp torrent_files/torrent.torrent $(pwd)"/mktorrent"
cd mktorrent
deluged
deluge-console add $(pwd)"/torrent.torrent" -p $(pwd)
cd ..
killall deluged