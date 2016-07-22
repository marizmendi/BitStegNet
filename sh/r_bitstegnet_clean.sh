#! /bin/sh
sudo rm mktorrent/file;
deluge-console recheck file;
wait 10;
sudo killall deluged;
sudo rm filename;