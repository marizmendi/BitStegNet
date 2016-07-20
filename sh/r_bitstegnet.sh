#! /bin/sh
sudo bin/bitstegnet 1;
sudo rm mktorrent/file;
sudo deluge-console recheck file;
sudo killall deluged