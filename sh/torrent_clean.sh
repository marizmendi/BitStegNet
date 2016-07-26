#! /bin/sh
deluged;
wait 10;
deluge-console rm file;
rm -rf mktorrent;
wait 10;
killall deluged;
