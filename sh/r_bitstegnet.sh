#! /bin/sh
sudo killall deluged;
sudo bin/bitstegnet 1;
sudo rm mktorrent/file;
sudo deluge-console recheck file;
