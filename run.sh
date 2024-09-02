#!/bin/bash
start=$1
port1=$((start+1))
port2=$((start+2))
port3=$((start+3))
python3 src/proxy_encryption_server.py -p $start > proxy.log 2>&1  &
python3 src/server.py -p $port1 -n $port1 $port2 $port3 -f data/$port1.json > node1.log 2>&1 &
python3 src/server.py -p $port2 -n $port1 $port2 $port3 -f data/$port2.json > node2.log 2>&1 &
python3 src/server.py -p $port3 -n $port1 $port2 $port3 -f data/$port3.json > node3.log 2>&1 &

sleep 1
python3 src/run.py -f startexp -s $port1