#!/bin/bash
c=http://0.0.0.0:600
c0=${c}0
c1=${c}1
c2=${c}2
c3=${c}3
s4=${c}4

nohup python3 client.py -p 6000 --peers $c1 $c2 &
nohup python3 client.py -p 6001 --peers $c0 $c2 &
nohup python3 shuffle_server.py -p 6004 &
sleep 5
echo "Shuffle start"
echo $c0/coinshuffle/new
echo "Shuffle alice"
curl -d '{"source":"alice","hidden_target":"AlicePrime","server_addr": "http://0.0.0.0:6004"}' \
   -H "Content-Type: application/json" -X POST \
   $c0/coinshuffle/new
echo "Shuffle bob"
curl -d '{"source":"bob","hidden_target":"BobPrime","server_addr": "http://0.0.0.0:6004"}' \
   -H "Content-Type: application/json" -X POST \
   $c1/coinshuffle/new
echo "Shuffle server start action"
curl $s4/coinshuffle/start
curl $c1/mine
curl $c1/chain | python3 -m json.tool
   
sleep 3
./kill.sh
