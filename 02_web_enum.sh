#!/bin/bash
mkdir web 
dir=$(pwd)
wordlist="/usr/share/SecLists/Discovery/Web-Content/raft-medium-directories.txt"
echo "=======start====="
dirsearch.py -u $1 -w $wordlist -e asp,aspx,php,php,html,txt,bak -o $dir/web/dirsearch.log -r 
echo "=======finished====="
whatweb -a 3 $1 |tee web/whatweb.log
echo "=======finished====="
nuclei -u $1 |tee web/nuclei.log
