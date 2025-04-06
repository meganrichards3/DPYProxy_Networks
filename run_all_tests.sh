#!/bin/bash

# Run this script from terminal by running "sh run_all_tests.sh"

# Define Arguments 
N=10 # number of times to call each website
frag_size=20 # size of the fragment
tcp_frag=True # whether to use TCP fragmentation
record_frag=False # whether to use record fragmentation
website_list_to_use="test" # list of websites to use (test, censored, popular)

# Loop to call test.py N times with the specified parameters WITH dpyproxy 
for ((i=1; i<=N; i++)); do
  echo "Running test iteration $i..."
  python3 test.py \
    --frag_size "$frag_size" \
    $( [ "$tcp_frag" = true ] && echo "--tcp_frag" ) \
    $( [ "$record_frag" = true ] && echo "--record_frag" ) \
    --dpyproxy \
    --website_list_to_use "$website_list_to_use" \
    --sample 0
done

# Loop to call test.py N times with the specified parameters WITHOUT dpyproxy 
for ((i=1; i<=N; i++)); do
  echo "Running test iteration $i..."
  python3 test.py \
    --website_list_to_use "$website_list_to_use" \
    --sample 0
done

echo "All $N tests completed."