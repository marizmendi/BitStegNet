#! /bin/sh
deluge-console config -s random_port false;
deluge-console config -s listen_ports "(9898,9898)";