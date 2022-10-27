#! /bin/bash
#nmap
mkdir nmap
nmap -p- -oN nmap/all_ports $1 -vvv
export ports=$(cat nmap/all_ports |grep "open"|cut -d "/" -f1|tr "\n" ","| sed 's/.$//')
echo $ports
nmap -p$ports -sC -sV $1 -oN nmap/services -vvv
