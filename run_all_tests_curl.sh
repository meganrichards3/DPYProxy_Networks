#!/bin/bash
N=100  # Define the number of tests to run for each website
file_path=controlled_website.txt #citizen_lab_censored_50.txt
# Define an array of frag sizes to iterate over
frag_sizes=(2 5 10 15 20 40 60 80 100)

# Run the tests for dpyproxy with different frag sizes
for frag_size in "${frag_sizes[@]}"; do
    for ((i=1; i<=N; i++)); do
    
        while IFS= read -r website; do
            echo "Running DPYProxy test $i / $N for website: $website with frag_size: $frag_size"
            # TCP Fragmentation Only!
            python test_curl_metrics.py \
                --website $website  \
                --setting dpyproxy \
                --tcp_frag  \
                --frag_size $frag_size 
            sleep 10
            # TLS Fragmentation Only!
            python test_curl_metrics.py \
                --website $website  \
                --setting dpyproxy \
                --record_frag  \
                --frag_size $frag_size 
            sleep 10
            # TCP and TLS Fragmentation
            python test_curl_metrics.py \
                --website $website  \
                --setting dpyproxy \
                --tcp_frag  \
                --record_frag \
                --frag_size $frag_size 
        done < $file_path
    done
    sleep 100
done

# Run tests for proxy baseline
for ((i=1; i<=N; i++)); do
    while IFS= read -r website; do
        echo "Running proxy baseline test $i / $N for website: $website"
        python test_curl_metrics.py \
            --website $website  \
            --setting proxy_baseline 
        sleep 10
    done < $file_path
done

sleep 100

# Run tests for baseline
for ((i=1; i<=N; i++)); do
    while IFS= read -r website; do
        echo "Running baseline test $i for website: $website"
        python test_curl_metrics.py \
            --website $website \
            --setting baseline 
        sleep 10
    done < $file_path
done
