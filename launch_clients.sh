#!/bin/bash
c=http://127.0.0.1:600
c0=${c}0
c1=${c}1
c2=${c}2
c3=${c}3
s4=${c}4

#nohup python3 client.py -p 6000 --peers $c1 $c2 &
nohup python3 client.py -p 6001 --peers $c0 $c2 &
nohup python3 client.py -p 6002 --peers $c0 $c1 &

