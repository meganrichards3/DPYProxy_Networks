#!/bin/bash
N=5  # Define the number of tests to run for each website
while IFS= read -r website; do
    for ((i=1; i<=N; i++)); do
        echo "Running test $i for website: $website"
        python3 test.py \
            --website $website  \
            --dpyproxy \
            --tcp_frag  \
            --frag_size 20 

        python3 test.py \
            --website $website
    done
        
    # Add your processing logic here
done < citizen_lab_censored.txt