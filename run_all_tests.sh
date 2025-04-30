#!/bin/bash
N=10  # Define the number of tests to run for each website

# Run the tests for dpyproxy 
for ((i=1; i<=N; i++)); do
    while IFS= read -r website; do
        echo "Running test $i for website: $website"
        python test.py \
            --website $website  \
            --setting dpyproxy \
            --tcp_frag  \
            --frag_size 5 
        sleep 10
    done < citizen_lab_censored_2.txt
done

sleep 100

# Run tests for proxy baseline
for ((i=1; i<=N; i++)); do
    while IFS= read -r website; do
        echo "Running test $i for website: $website"
        python test.py \
            --website $website  \
            --setting proxy_baseline 
        sleep 10
    done < citizen_lab_censored_2.txt
done

sleep 100
# Run tests for baseline
for ((i=1; i<=N; i++)); do
    while IFS= read -r website; do
        echo "Running test $i for website: $website"
        python test.py \
            --website $website \
            --setting baseline 
        sleep 10
    done < citizen_lab_censored_2.txt
done
