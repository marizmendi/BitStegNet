#! /bin/sh
sudo bin/bitstegnet 1;
sudo rm mktorrent/file;
deluge-console recheck file;
wait 10;
sudo killall deluged;
cat filename | base64 --decode > $(cat "file." $1)