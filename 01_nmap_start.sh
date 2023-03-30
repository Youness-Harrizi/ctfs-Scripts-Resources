#! /bin/bash

# Parse command-line arguments
while [[ $# -gt 0 ]]
do
    key="$1"
    echo "key : $key"
    echo " ext: $ext"
    case $key in
        -f|--fast)
            fast=true
            shift
            ;;
	-u|--udp)
            udp=true
            shift
            ;;
        *)
            target="$1"
            shift
            ;;
    esac
done

# Create nmap directory
mkdir -p nmap

# Perform Nmap scan to identify all open ports
nmap_cmd="nmap -Pn -p- -oN nmap/all_ports_$target $target -vvv"
echo $nmap_cmd
if [[ $fast == true ]]; then
    nmap_cmd+=" --max-rtt-timeout 100ms --max-retries 1"
fi
$nmap_cmd

# Extract list of open ports from all_ports file
ports=$(cat "nmap/all_ports_$target" | grep "open" |grep -v "Warning" | cut -d "/" -f1 | tr "\n" "," | sed 's/.$//')
echo "Open ports: $ports"

# Perform Nmap scan on open ports to identify services and vulnerabilities
nmap_cmd="nmap -Pn -p$ports -sC -sV $target -oN nmap/services_$target -vvv"
if [[ $fast == true ]]; then
    nmap_cmd+=" --max-rtt-timeout 100ms --max-retries 1"
fi
$nmap_cmd

if [[ $udp == true ]]; then
    echo "start udp scan"
    nmap -sU -oN nmap/all_ports_udp $target -vvv
