#!/bin/bash
mkdir web 
dir=$(pwd)
wordlist="/usr/share/secLists/Discovery/Web-Content/raft-medium-directories.txt"
echo "=======start whatweb====="
whatweb -a 3 $1 |tee web/whatweb.log
echo "=======start nuclei ====="
nuclei -u $1 |tee web/nuclei.log
echo "=======start nikto ====="
nikto -h $1 |tee web/nikto.log
echo "=======start dirsearch====="
feroxbuster -u $1 -w $wordlist -o $dir/feroxbuster.log -t 16 -x html,php,asp,aspx,jsp -C 404,403 
