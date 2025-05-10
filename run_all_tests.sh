#!/bin/bash
N=50  # Define the number of tests to run for each website
frag_size=5
file_path=controlled_website.txt #citizen_lab_censored_50.txt
# Run the tests for dpyproxy 
for ((i=1; i<=N; i++)); do
    while IFS= read -r website; do
        echo "Running test $i for website: $website"
        python test.py \
            --website $website  \
            --setting dpyproxy \
            --tcp_frag  \
            --frag_size $frag_size
        sleep 10
    done < $file_path
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
    done < $file_path
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
    done < $file_path
done
