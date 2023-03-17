#!/bin/bash
mkdir web 
dir=$(pwd)
wordlist="/usr/share/SecLists/Discovery/Web-Content/raft-medium-directories.txt"
echo "=======start whatweb====="
whatweb -a 3 $1 |tee web/whatweb.log
echo "=======start nuclei ====="
nuclei -u $1 |tee web/nuclei.log
echo "=======start nikto ====="
nikto -h $1 |tee web/nikto.log
echo "=======start dirsearch====="
dirsearch.py -u $1 -w $wordlist -o $dir/web/dirsearch.log -r -t 16
