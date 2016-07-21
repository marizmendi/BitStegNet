#! /bin/sh
sudo deluged;
sudo rm mktorrent/file;
sudo deluge-console recheck file;
sudo killall deluged;