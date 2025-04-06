import pyshark
import subprocess
import socket
import os
import time
import threading
import argparse
import pandas as pd 
import uuid
from tqdm import tqdm
import random


def process_packets(capture_file_path, website, id, verbose=False): 
    if verbose:
        print(f"Packet capture for {website} saved to {capture_file_path}")
    metrics = {}
    metrics["website"] = website
    metrics["id"] = id
    metrics["date"] = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        filtered_packets = pyshark.FileCapture(capture_file_path)
        packets = list(filtered_packets)  # Force load all packets
        packet_count = len(packets)
        metrics["packet_count"] = packet_count
        if verbose:
            print(f"Captured {packet_count} packets for {website}.")
        
        # Store packet sizes in a list
        packet_sizes = [int(packet.length) for packet in packets if hasattr(packet, 'length')]
        metrics["packet_sizes"] = str(packet_sizes)
        
        # Calculate total packet size
        total_size = sum(packet_sizes)
        metrics["packet_total_size"] = total_size
        if verbose:
            print(f"Total size of captured packets: {total_size} bytes.")
        
        # Calculate packet distribution
        if packet_sizes:
            min_size = min(packet_sizes)
            max_size = max(packet_sizes)
            average_size = total_size / len(packet_sizes)
            metrics["packet_min_size"] = min_size
            metrics["packet_max_size"] = max_size
            metrics["packet_average_size"] = average_size
            if verbose:
                print(f"Packet size distribution - Min: {min_size} bytes, Max: {max_size} bytes, Average: {average_size:.2f} bytes.")
        else:
            metrics["packet_min_size"] = 0
            metrics["packet_max_size"] = 0
            metrics["packet_average_size"] = 0
            if verbose:
                print("No packets with size information were captured.")
        
        tcp_packets = [p for p in packets if hasattr(p, 'tcp')]
        
        if tcp_packets:
            # Look for retransmissions
            retransmissions = [p for p in tcp_packets if hasattr(p.tcp, 'analysis_retransmission')]
            # Look for duplicate ACKs (potential indicator of packet loss)
            duplicate_acks = [p for p in tcp_packets if hasattr(p.tcp, 'analysis_duplicate_ack')]
            # Look for fast retransmissions
            fast_retrans = [p for p in tcp_packets if hasattr(p.tcp, 'analysis_fast_retransmission')]
            
            # Calculate packet loss metrics
            total_tcp = len(tcp_packets)
            retrans_count = len(retransmissions)
            dup_ack_count = len(duplicate_acks)
            fast_retrans_count = len(fast_retrans)
            
            # Calculate packet loss percentage
            if total_tcp > 0:
                retrans_percentage = (retrans_count / total_tcp) * 100
                if verbose:
                    print(f"TCP packets: {total_tcp}")
                    print(f"Retransmissions: {retrans_count} ({retrans_percentage:.2f}%)")
                    print(f"Duplicate ACKs: {dup_ack_count}")
                    print(f"Fast Retransmissions: {fast_retrans_count}")
                
                metrics["tcp_count"] = total_tcp
                metrics["tcp_retransmissions"] = retrans_count
                metrics["tcp_duplicate_acks"] = dup_ack_count
                metrics["tcp_fast_retransmissions"] = fast_retrans_count
                metrics["tcp_retransmission_percentage"] = retrans_percentage
            else:
                metrics["tcp_count"] = 0
                metrics["tcp_retransmissions"] = 0
                metrics["tcp_duplicate_acks"] = 0
                metrics["tcp_fast_retransmissions"] = 0
                metrics["tcp_retransmission_percentage"] = 0
                if verbose:
                    print("No TCP packets found for loss analysis.")
            
            # Calculate RTT (Round-Trip Time)
            rtt_values = []
            for packet in tcp_packets:
                if hasattr(packet.tcp, 'analysis_ack_rtt'):
                    rtt_values.append(float(packet.tcp.analysis_ack_rtt))
            
            if rtt_values:
                min_rtt = min(rtt_values)
                max_rtt = max(rtt_values)
                avg_rtt = sum(rtt_values) / len(rtt_values)
                metrics["tcp_min_rtt"] = min_rtt
                metrics["tcp_max_rtt"] = max_rtt
                metrics["tcp_avg_rtt"] = avg_rtt
                if verbose:
                    print(f"RTT - Min: {min_rtt:.6f}s, Max: {max_rtt:.6f}s, Average: {avg_rtt:.6f}s")
            else:
                metrics["tcp_min_rtt"] = 0
                metrics["tcp_max_rtt"] = 0
                metrics["tcp_avg_rtt"] = 0
                if verbose:
                    print("No RTT information available in TCP packets.")
        else:
            metrics["tcp_count"] = 0
            metrics["tcp_retransmissions"] = 0
            metrics["tcp_duplicate_acks"] = 0
            metrics["tcp_fast_retransmissions"] = 0
            metrics["tcp_retransmission_percentage"] = 0
            metrics["tcp_min_rtt"] = 0
            metrics["tcp_max_rtt"] = 0
            metrics["tcp_avg_rtt"] = 0
            if verbose:
                print("No TCP packets captured for loss analysis.")

        # For UDP packets (if applicable)
        udp_packets = [p for p in packets if hasattr(p, 'udp')]
        metrics["udp_count"] = len(udp_packets)
        if udp_packets:
            if verbose:
                print(f"UDP packets: {len(udp_packets)}")

            # UDP doesn't have built-in loss detection, but you can look for 
            # sequence gaps if the protocol over UDP has sequence numbers
            # For UDP packets (if applicable)

            # Try to detect UDP packet loss for common protocols
            # 1. Look for RTP (Real-time Transport Protocol)
            rtp_packets = [p for p in udp_packets if hasattr(p, 'rtp')]
            metrics["rtp_count"] = len(rtp_packets)

            if rtp_packets and len(rtp_packets) > 1:
                if verbose:
                    print(f"Found {len(rtp_packets)} RTP packets")
                
                # Extract sequence numbers
                rtp_seq_nums = [int(p.rtp.seq) for p in rtp_packets if hasattr(p.rtp, 'seq')]
                metrics["rtp_sequence_numbers"] = rtp_seq_nums
                
                # Sort sequence numbers
                rtp_seq_nums.sort()
                
                # Count gaps in sequence
                if rtp_seq_nums:
                    expected_packets = rtp_seq_nums[-1] - rtp_seq_nums[0] + 1
                    missing_packets = expected_packets - len(rtp_seq_nums)
                    metrics["rtp_missing_packets"] = missing_packets
                    
                    if missing_packets > 0:
                        loss_percentage = (missing_packets / expected_packets) * 100
                        if verbose:
                            print(f"Detected {missing_packets} missing RTP packets ({loss_percentage:.2f}% loss)")
                        metrics["rtp_missing_packets_percentage"] = loss_percentage
                        
                    else:
                        metrics["rtp_missing_packets_percentage"] = 0
                        if verbose:
                            print("No RTP packet loss detected")
            
            # 2. Look for DNS queries and responses
            dns_packets = [p for p in udp_packets if hasattr(p, 'dns')]
            
            if dns_packets:
                metrics["dns_count"] = len(dns_packets)
                if verbose:
                    print(f"Found {len(dns_packets)} DNS packets")
                
                # Group by transaction ID
                dns_transactions = {}
                for p in dns_packets:
                    if hasattr(p.dns, 'id'):
                        trans_id = p.dns.id
                        if trans_id in dns_transactions:
                            dns_transactions[trans_id].append(p)
                        else:
                            dns_transactions[trans_id] = [p]
                
                # Look for incomplete transactions (potentially lost packets)
                incomplete = [tid for tid, packets in dns_transactions.items() if len(packets) == 1]
                
                if incomplete:
                    metrics["dns_incomplete_transactions"] = len(incomplete)
                    if verbose:
                        print(f"Found {len(incomplete)} DNS queries without responses (potential packet loss)")
                else: 
                    metrics["dns_incomplete_transactions"] = 0
                    if verbose:
                        print(f"No incomplete DNS transactions detected")
            else: 
                metrics["dns_count"] = 0
                metrics["dns_incomplete_transactions"] = 0
                if verbose:
                    print("No DNS packets captured.")
        filtered_packets.close()
    except Exception as e:
        if verbose:
            print(f"Error analyzing capture file: {e}")
    return metrics
    
def make_results_folders(dpyproxy, website, param_log_string = ""): 
     # Define folder structure for saving results
    label = ""
    if dpyproxy:
        label = "dpyproxy"
    else: 
        label = "baseline"

    # Create result saving folder
    website_base = website.replace("https://", "").replace("http://", "").replace("www", "").replace(".", "_").replace("/", "__")
    print(f"Website base name: {website_base}")
    folder_name = os.path.join(os.getcwd(), "results", f"{label}", param_log_string, website_base)
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)
    return folder_name

def set_up(record_frag=False, tcp_frag=False, frag_size=20):

    base_command = f"nohup python3 main.py --frag_size {frag_size}"
    if record_frag:
        base_command += " --record_frag"
    if tcp_frag:
        base_command += " --tcp_frag"

    base_command += " --port 4433 &"
    print(f"Running {base_command}")
    os.system(base_command)
    return 
  

def capture_website_traffic(website, interface="en0", dpyproxy=False, result_folder="results", verbose=False):
    """Capture network traffic while accessing a website."""
    # Create output filenames based on the website name
    id = str(uuid.uuid4())

    output_file = os.path.abspath(os.path.join(result_folder, "captures", f"{id}_output.txt"))
    capture_file = os.path.abspath(os.path.join(result_folder, "captures", f"{id}_capture.pcap"))
    if not os.path.exists(os.path.join(result_folder, "captures")):
        os.makedirs(os.path.join(result_folder, "captures"), exist_ok=True)
    if verbose:
        print(f"Capture file: {capture_file}")
        print(f"Output file: {output_file}")

    try:
        
        # Create a function for capture to run in a separate thread
        def capture_packets():
            try:
                capture = pyshark.LiveCapture(interface=interface, output_file=capture_file)
                capture.sniff(timeout=15)  # Set a timeout of 15 seconds
                return capture
            except Exception as e:
                if verbose:
                    print(f"Capture error: {e}")
                return None
        
        # Start capture in a thread 
        if verbose:
            print(f"Starting capture for {website}...")
        capture_thread = threading.Thread(target=capture_packets)
        capture_thread.daemon = True
        capture_thread.start()
        
        # Wait a moment for capture to start
        time.sleep(2)

        # Send the request with curl (following redirects with -L)
        if dpyproxy:
            if website.startswith("https://"):
                curl_command = f"curl -L -p -x localhost:4433 -o '{output_file}' {website}"
            else:
                curl_command = f"curl -L -p -x localhost:4433 -o '{output_file}' https://{website}"
        else: 
            if website.startswith("https://"):
                curl_command = f"curl -L -o '{output_file}' {website}"
            else:
                curl_command = f"curl -L -o '{output_file}' https://{website}"
        
        if verbose:
            print(f"Executing: {curl_command}")
        subprocess.run(curl_command, shell=True, check=False)

        time.sleep(5)  
        
        metrics = {}
        # Check if file exists before analyzing
        if os.path.exists(capture_file):
            packet_metrics = process_packets(capture_file, website, id, verbose=verbose)
            if verbose:
                print("Packet analysis completed.")
            metrics.update(packet_metrics)
        else:
            if verbose:
                print(f"Error: Capture file {capture_file} was not created.")
        
        for x in metrics:
            if verbose:
                print(f"{x}: {metrics[x]}")

        # Save metrics to a CSV file
        metrics_file = os.path.join(result_folder, "metrics.csv")
        ## Add params + experiment id
        param_dict = {key_value.split("=")[0]: key_value.split("=")[1] for key_value in param_log_string.split("__")}
        for param in param_dict.keys():
            metrics[f"param_{param}"] = param_dict.get(param, None)
        
        metrics["id"] = id

        if os.path.exists(metrics_file):
            # Append to the existing file (for multiple runs)
            metrics_df = pd.DataFrame(metrics, index=[0])
            metrics_df.to_csv(metrics_file, mode='a', header=False, index=False)
        else:
            # Create a new file
            metrics_df = pd.DataFrame(metrics, index=[0])
            metrics_df.to_csv(metrics_file, index=False)
        return True
    
    except Exception as e:
        print(f"Error processing {website}: {e}")
        return False

def get_censored_websites(): 
    # Read the list of censored websites from a CSV file
    try:
        csv_file_path = os.path.join(os.getcwd(), "citizen_lab_censored.csv")
        if not os.path.exists(csv_file_path):
            print(f"Error: {csv_file_path} does not exist.")
            return []

        # Load the CSV file into a DataFrame
        df = pd.read_csv(csv_file_path)

        # Assuming the column containing websites is named 'url'
        if 'url' not in df.columns:
            print("Error: 'url' column not found in the CSV file.")
            return []

        # Return the list of websites
        return df['url'].tolist()
    
    except Exception as e:
        print(f"Error reading censored websites: {e}")
        return []
    
if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Set up test parameters.")
    parser.add_argument("--frag_size", type=int, default=20, help="Fragment size for the test.")
    parser.add_argument("--tcp_frag", action="store_true", default=False, help="Enable TCP fragmentation.")
    parser.add_argument("--record_frag", action="store_true", default=False, help="Enable recording of fragments.")
    parser.add_argument("--dpyproxy", action="store_true", default=False, help="Use dpyproxy.")
    parser.add_argument("--website_list_to_use", type=str, choices=["censored", "popular", "test"], default="test", help="Website list to use (censored, popular, or test).")
    parser.add_argument("--sample", type=int, default=0, help="Number of samples to use, if randomly sampling from the list of webistes.")
    parser.add_argument("--verbose", action="store_true", default=False, help="Enable verbose output (all the printouts).")
    
    args = parser.parse_args()

    # Define variables from arguments 
    dpyproxy = args.dpyproxy
    tcp_frag = args.tcp_frag
    record_frag = args.record_frag
    frag_size = args.frag_size
    website_list_to_use = args.website_list_to_use
    sample = args.sample

    if dpyproxy and not (tcp_frag or record_frag):
        print("Warning: dpyproxy is enabled but no fragmentation options are selected. Setting TCP Fragmentation to True.")
        tcp_frag = True

    # List of websites to analyze
    if website_list_to_use == "censored":
        websites = get_censored_websites()
        if not websites:
            print("No websites found in the censored list.")
            exit(1)
    elif website_list_to_use == "popular":
        websites = [
            "google.com",
            "facebook.com",
            "twitter.com",
            "youtube.com",
            "instagram.com"
        ]
    elif website_list_to_use == "test":
        websites = [
            "wikipedia.org"
        ]

    if sample > 0 and sample < len(websites):
        websites = random.sample(websites, sample)
        print(f"Sampling {sample} websites from the list.")
    elif sample > len(websites):
        print(f"Sample size {sample} exceeds the number of available websites. Using all websites.")
    else: 
        print(f"Using all {len(websites)} websites from the list.")
    interface = "en0"  # Wifi 

    if dpyproxy: 
        # Set up dpyproxy
        set_up(record_frag=record_frag, tcp_frag=tcp_frag, frag_size=frag_size)
        param_log_string = f"frag_size={args.frag_size}__tcp_frag={args.tcp_frag}__record_frag={args.record_frag}"
        time.sleep(2)
    else: 
        param_log_string = f"dpyproxy={args.dpyproxy}"
    
    # Process each website
    for website in tqdm(websites, desc="Processing websites"):
        print(f"\n{'='*50}\nProcessing {website}\n{'='*50}")
        result_folder = make_results_folders(dpyproxy, website, param_log_string=param_log_string)
        # Run capture_website_traffic sequentially to avoid asyncio issues
        capture_website_traffic(website, interface, dpyproxy, result_folder, verbose=args.verbose)
        
    print("\nAll websites processed!")