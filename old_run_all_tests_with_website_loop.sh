#!/bin/bash

########## DOES NOT WORK!!!!!!!!! ##############








# Run this script from terminal by running "sh run_all_tests.sh"
# To run in the background, use "nohup sh run_all_tests.sh &"

# Define Arguments 
N=1 # number of times to call each website
frag_size=20 # size of the fragment
website_list_to_use="popular" # list of websites to use (test, censored, popular)

# Loop to call test.py N times with the specified parameters WITH dpyproxy 
# for ((i=1; i<=N; i++)); do
#   echo "Running test iteration $i..."
#   python3 test.py \
#     --frag_size "$frag_size" \
#     --tcp_frag \
#     --dpyproxy \
#     --website_list_to_use "$website_list_to_use" \
#     --verbose 
# done

# Loop to call test.py N times with the specified parameters WITHOUT dpyproxy 
for ((i=1; i<=N; i++)); do
  echo "Running test iteration $i..."
  python3 test_with_website_loop.py \
    --website_list_to_use "$website_list_to_use" \
    --verbose 
done

echo "All $N tests completed."