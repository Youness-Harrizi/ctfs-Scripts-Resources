#!/bin/bash
mkdir web 
dir=$(pwd)
wordlist1="/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
wordlist2="/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt"

echo "=======start whatweb====="
whatweb -a 3 $1 |tee "web/whatweb_$2.log"


echo "=======start feroxbuster with directories wordlist====="
feroxbuster -u $1 -t 16 -C 404,403 -o  "web/dir_$2.log" -w $wordlist1 -k

echo "=======start feroxbuster with files wordlist====="
feroxbuster -u $1 -t 16 -C 404,403 -o  "web/files_$2.log" -w $wordlist2 -k -x php,txt,bak,zip,html

echo "=======start nuclei ====="
nuclei -u $1 |tee "web/nuclei_$2.log"

echo "=======start nikto ====="
nikto -h $1 |tee "web/nikto_$2.log"
