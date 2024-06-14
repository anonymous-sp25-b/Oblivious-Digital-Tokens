#!/bin/bash

command() {
    echo " " | ./apps/openssl s_client -connect localhost:4433 -quiet -no_ign_eof
}

for i in {1..1000}; do
    >&2 echo "$i";
    cd $1;
    start="$(date +'%s.%N')";
    command &> /dev/null;
    echo "$(date +"%s.%N - ${start}" | bc)"
done


# Taken from https://stackoverflow.com/questions/32752046/linux-time-command-with-high-precision
