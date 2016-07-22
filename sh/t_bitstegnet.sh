#! /bin/sh
echo $(cat $1 | base64) | sudo bin/bitstegnet 0;
sudo killall deluged;
sudo rm filename;