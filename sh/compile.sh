#! /bin/sh
sudo rm -rf bin;
sudo mkdir bin;
sudo gcc src/bitstegnet.c -o bin/bitstegnet -lnetfilter_queue -lnfnetlink -lm -std=c99;