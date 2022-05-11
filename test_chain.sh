#!/bin/bash
c0=http://0.0.0.0:6000/
c1=http://0.0.0.0:6001/
c2=http://0.0.0.0:6002/
nohup python3 client.py -p 6000 --peers $c1 $c2 &
nohup python3 client.py -p 6001 --peers $c0 $c2 &
nohup python3 client.py -p 6002 --peers $c0 $c1 &
sleep 3
echo "Now curl start"
curl -d '{"source":"alice","target":"b","amount":"500"}' \
  -H "Content-Type: application/json" -X POST \
  http://0.0.0.0:6002/transactions/new

curl http://0.0.0.0:6002/mine
curl http://0.0.0.0:6001/resolve
curl http://0.0.0.0:6001/chain | python3 -m json.tool

sleep 3

#./kill.sh
