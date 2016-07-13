#! /bin/sh
deluge-console resume file;
sudo bin/bitstegnet 1;
rm mktorrent/file;
deluge-console pause file;
deluge-console recheck file;
