#!/bin/bash 

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; export PATH

rm sslblacklist.csv* ; wget https://sslbl.abuse.ch/blacklist/sslblacklist.csv
