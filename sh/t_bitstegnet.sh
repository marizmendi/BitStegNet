#! /bin/sh
deluge-console resume file;
echo $1 | sudo bin/bitstegnet 0;
deluge-console pause file;