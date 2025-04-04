import sys
import os
import argparse
import pyshark
import subprocess
import time
import socket
import pandas as pd


def set_up(record_frag=False, tcp_frag=False, frag_size=20):
    # Check if the process is already running on the port
    port_in_use = False
    check_command = f"netstat -an | grep 4433 | grep LISTEN"
    result = subprocess.run(check_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.stdout:
        port_in_use = True

    if not port_in_use:
        base_command = f"nohup python3 main.py --frag_size {frag_size}"
        if record_frag:
            base_command += " --record_frag"
        if tcp_frag:
            base_command += " --tcp_frag"

        base_command += " --port 4433 &"
        print(f"Running {base_command}")
        os.system(base_command)
    else:
        print("Process is already running on port 4433. Skipping setup.")


def run_tests(website="wikipedia.org", folder_name="results", dpyproxy = False):
    metrics = {}

    label = ""
    if dpyproxy:
        label = "dpyproxy"
    else: 
        label = "baseline"
    # Create result saving folder

    folder_name = os.path.join(folder_name, website.replace(".", "_"), label)
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)

    print(f"\n########## Starting tests for {website} ##########")

    # Resolve the IP address of the website
    website_ip = socket.gethostbyname(website)
    print(f"Resolved IP for {website}: {website_ip}")

    # Curl test for round trip time
    curl_output_file = os.path.join(folder_name, "curl_output.txt")
    print("Running curl test...")
    
    with open(curl_output_file, "w") as curl_file:
        curl_command = ["curl", "-H", "Cache-Control: no-cache", "-o", "/dev/null", "-s", "-w", "%{time_total}\n", website]
        if dpyproxy:
            curl_command.extend(["-p", "-x", "localhost:4433"])
        subprocess.run(
            curl_command,
            stdout=curl_file, stderr=subprocess.DEVNULL
        )

    # Read the first line of the curl_file to get the total time
    with open(curl_output_file, "r") as curl_file:
        curl_time_total = float(curl_file.readline().strip())
        metrics["curl_time_total"] = curl_time_total
  
    print(f"Curl test completed. Output saved to {curl_output_file}")

    # Ping test for RTT (ICMP packets)
    ping_output_file = os.path.join(folder_name, "ping_output.txt")
    print("Running ping test...")
    with open(ping_output_file, "w") as ping_file:
        
        ping_command = ["ping", "-c", "10", website_ip]
        if dpyproxy:
            ping_command.extend(["-p", "-x", "localhost:4433"])
        ping_result = subprocess.run(ping_command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        ping_file.write(ping_result.stdout.decode())

    # Extract RTT and packet loss from the ping output
    rtt_lines = ping_result.stdout.decode().splitlines()
      
    # Extract packet loss percentage
    packet_loss_line = next((line for line in rtt_lines if "packets transmitted" in line and "packet loss" in line), None)
    packet_timing_line = next((line for line in rtt_lines if "round-trip min/avg/max/stddev" in line), None)

    if packet_loss_line:
        packet_sent = packet_loss_line.split(",")[0].strip().split(" ")[0]
        packet_received = packet_loss_line.split(",")[1].strip().split(" ")[0]
        packet_loss = packet_loss_line.split(",")[2].strip().split(" ")[0]
        print(f"Packet Loss: {packet_loss}%")
    else:
        packet_sent = None
        packet_received = None
        packet_loss = None
        print("Failed to calculate packet loss.")

    if packet_timing_line: 
        packet_min = packet_timing_line.split("=")[1].strip().split("/")[0]
        packet_avg = packet_timing_line.split("=")[1].strip().split("/")[1]
        packet_max = packet_timing_line.split("=")[1].strip().split("/")[2]
        packet_stddev = packet_timing_line.split("=")[1].strip().split("/")[3].split(" ")[0]
        print(packet_min, packet_max, packet_avg, packet_stddev)
    else: 
        packet_min = None
        packet_avg = None
        packet_max = None
        packet_stddev = None
        print("Failed to calculate packet timing.")

    metrics["packet_sent"] = packet_sent
    metrics["packet_received"] = packet_received
    metrics["packet_loss"] = packet_loss
    metrics["packet_min"] = packet_min
    metrics["packet_max"] = packet_max
    metrics["packet_stddev"] = packet_stddev
    metrics["packet_avg"] = packet_avg

    print(f"Ping test completed. Output saved to {ping_output_file}")

    print("\n########## All tests completed ##########")
    # Save metrics to a file
    metrics_file = os.path.join(folder_name, "metrics.csv")
    metrics["website"] = website
    metrics["website_ip"] = website_ip
    metrics["label"]  = label

    metrics_df = pd.DataFrame(metrics, index=[0])
    metrics_df.to_csv(metrics_file, index=False)
    print(metrics)
    print(f"Metrics saved to {metrics_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Set up test parameters.")
    parser.add_argument("--frag_size", type=int, default=20, help="Fragment size for the test.")
    parser.add_argument("--tcp_frag", action="store_true", default=False, help="Enable TCP fragmentation.")
    parser.add_argument("--record_frag", action="store_true", default=False, help="Enable recording of fragments.")
    parser.add_argument("--website", type=str, default="google.com", help="Website to connect to.")
    args = parser.parse_args()

    # Clear any DNS cache on the system
    os.system("sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder")

    set_up(record_frag=args.record_frag, tcp_frag=args.tcp_frag, frag_size=args.frag_size)

    run_tests(website=args.website)

    sys.exit(0)
