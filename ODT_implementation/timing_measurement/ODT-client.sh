#!/bin/bash

command() {
    ./application aaa -server:127.0.0.1 -port:4433 2> /dev/null
}

for i in {1..1000}; do
    >&2 echo "$i";
    cd $1;
    start="$(date +'%s.%N')";
    command | grep -o -E 'Heartbeat: [0-9.]+' | tr -d -c 0-9. #&> /dev/null;
    echo ", $(date +"%s.%N - ${start}" | bc)"
done


# Taken from https://stackoverflow.com/questions/32752046/linux-time-command-with-high-precision
