#! /bin/sh
sudo rm -rf bin;
sudo mkdir bin;
sudo gcc src/timeshifter.c -o bin/timeshifter -lnetfilter_queue -lnfnetlink -lm;
sudo gcc src/stegnet.c -o bin/stegnet -lnetfilter_queue -lnfnetlink -lm -std=c99;
sudo gcc src/bitstegnet.c -o bin/bitstegnet -lnetfilter_queue -lnfnetlink -lm -std=c99;