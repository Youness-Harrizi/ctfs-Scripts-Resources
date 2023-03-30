#!/bin/bash
mkdir web 
dir=$(pwd)
wordlist="/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"

echo "=======start whatweb====="
whatweb -a 3 $1 |tee "web/whatweb_$2.log"


echo "=======start feroxbuster with no wordlist====="
feroxbuster -u $1 -t 16 -C 404,403 -o  "web/dir_$2.log" -k

echo "=======start nikto ====="
nikto -h $1 |tee "web/nikto_$2.log"
