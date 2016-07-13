#! /bin/sh
mkdir mktorrent
cd mktorrent
dd if=/dev/urandom iflag=fullblock of=file bs=32k count=64
mktorrent -a" http://explodie.org:6969/announce, http://mgtracker.org:2710/announce, udp://9.rarbg.to:2710/announce, udp://9.rarbg.me:2710/announce, udp://9.rarbg.com:2710/announce, http://tracker.tfile.me/announce, udp://tracker.coppersurfer.tk:6969/announce, udp://tracker.opentrackr.org:1337/announce" -l 15 -o "torrent.torrent" ./file
deluged
deluge-console add $(pwd)"/torrent.torrent" -p $(pwd)
cp torrent.torrent ../torrent_files/torrent.torrent
cd ..