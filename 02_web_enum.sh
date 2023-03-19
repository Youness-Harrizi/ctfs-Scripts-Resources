#!/bin/bash
mkdir web 
dir=$(pwd)
wordlist="/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
echo "=======start whatweb====="
whatweb -a 3 $1 |tee web/whatweb.log
echo "=======start nuclei ====="
nuclei -u $1 |tee web/nuclei.log
echo "=======start nikto ====="
nikto -h $1 |tee web/nikto.log
echo "=======start feroxbuster====="
feroxbuster -u $1 -w $wordlist -t 16 -x html,php,asp,aspx,jsp -C 404,403  -n -o  web/feroxbuster.log -k
