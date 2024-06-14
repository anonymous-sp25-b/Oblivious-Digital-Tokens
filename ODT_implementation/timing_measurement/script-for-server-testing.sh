#!/bin/bash
sum=0
for i in {1..1000}; do >&2 echo "$i";
                     curl -w '%{time_total}\n' https://127.0.0.1:4433 -m 2 -o /dev/null -s -k;
done
