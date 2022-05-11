#!/bin/bash
c=http://127.0.0.1:600
c0=${c}0
c1=${c}1
c2=${c}2
c3=${c}3
s4=${c}4

nohup python3 client.py -p 6000 --peers $c1 $c2 &
nohup python3 client.py -p 6001 --peers $c0 $c2 &
nohup python3 client.py -p 6002 --peers $c0 $c1 &

echo "Start shuffle server..."
nohup python3 shuffle_server.py -p 6004 &
sleep 5

echo "clients register for shuffle...."
curl -d '{"source":"alice","hidden_target":"AlicePrime","server_addr": "http://127.0.0.1:6004"}' -H "Content-Type: application/json" -X POST $c0/coinshuffle/new
sleep 2
curl -d '{"source":"bob","hidden_target":"BobPrime","server_addr": "http://127.0.0.1:6004"}' -H "Content-Type: application/json" -X POST  $c1/coinshuffle/new
sleep 2
curl -d '{"source":"charlie","hidden_target":"CharliePrime","server_addr": "http://127.0.0.1:6004"}' -H "Content-Type: application/json" -X POST $c2/coinshuffle/new
sleep 2
echo "Shuffle server start action"
curl $s4/coinshuffle/start
sleep 5
curl $c1/mine
curl $c1/chain | python3 -m json.tool
   
sleep 3
#./kill.sh
