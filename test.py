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
import socket



##################################### Packet Analysis Functions #####################################
def calculate_packet_size_metrics(packets, prefix = "all",  id = "",  capture_file_path = "", print_out_packets = False, verbose = False): 
    """
    Calculate packet size metrics for the captured packets. This is used on all packets, and also on subsets (e.g. TCP packets alone)
    """
    packet_size_metrics = {}
    packet_count = len(packets)
    packet_size_metrics[f"{prefix}_packet_count"] = packet_count
    if verbose:
            print(f"Captured {packet_count} packets for {prefix}.")
    # Store packet sizes in a list
    packet_sizes = [int(packet.length) for packet in packets if hasattr(packet, 'length')]
    packet_size_metrics[f"{prefix}_packet_sizes"] = str(packet_sizes)

    # Calculate total packet size
    total_size = sum(packet_sizes)
    packet_size_metrics[f"{prefix}_packet_total_size"] = total_size
    if verbose:
        print(f"Total size of captured packets: {total_size} bytes.")
    if print_out_packets:
        with open(os.path.join(os.path.dirname(capture_file_path), f"{id}_packets.txt"), "w") as packet_file:
            for packet in packets:
                packet_file.write(str(packet) + "\n")
    
    # Calculate packet size distribution
    if packet_sizes:
        min_size = min(packet_sizes)
        max_size = max(packet_sizes)
        average_size = total_size / len(packet_sizes)
        packet_size_metrics[f"{prefix}_packet_min_size"] = min_size
        packet_size_metrics[f"{prefix}_packet_max_size"] = max_size
        packet_size_metrics[f"{prefix}_packet_average_size"] = average_size
        if verbose:
            print(f"Packet size distribution - Min: {min_size} bytes, Max: {max_size} bytes, Average: {average_size:.2f} bytes.")
    else:
        packet_size_metrics[f"{prefix}_packet_min_size"] = 0
        packet_size_metrics[f"{prefix}_packet_max_size"] = 0
        packet_size_metrics[f"{prefix}_packet_average_size"] = 0
        if verbose:
            print("No packets with size information were captured.")

    return packet_size_metrics

def calculate_tcp_metrics(all_packets, verbose = False): 
    """
    Analyze TCP packets for retransmissions, duplicate ACKs, and RTT."""
    tcp_metrics = {}
    tcp_packets = [p for p in all_packets if hasattr(p, 'tcp')]
    tcp_size_metrics = calculate_packet_size_metrics(packets = tcp_packets, prefix = "tcp", id = None, capture_file_path = None, verbose=False)
    tcp_metrics.update(tcp_size_metrics)
        
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
            
            tcp_metrics["tcp_count"] = total_tcp
            tcp_metrics["tcp_retransmissions"] = retrans_count
            tcp_metrics["tcp_duplicate_acks"] = dup_ack_count
            tcp_metrics["tcp_fast_retransmissions"] = fast_retrans_count
            tcp_metrics["tcp_retransmission_percentage"] = retrans_percentage

            # Calculate RTT (Round-Trip Time)
            rtt_values = []
            for packet in tcp_packets:
                if hasattr(packet.tcp, 'analysis_ack_rtt'):
                    rtt_values.append(float(packet.tcp.analysis_ack_rtt))
            
            if rtt_values:
                min_rtt = min(rtt_values)
                max_rtt = max(rtt_values)
                avg_rtt = sum(rtt_values) / len(rtt_values)
                tcp_metrics["tcp_min_rtt"] = min_rtt
                tcp_metrics["tcp_max_rtt"] = max_rtt
                tcp_metrics["tcp_avg_rtt"] = avg_rtt
                if verbose:
                    print(f"RTT - Min: {min_rtt:.6f}s, Max: {max_rtt:.6f}s, Average: {avg_rtt:.6f}s")
            else:
                tcp_metrics["tcp_min_rtt"] = 0
                tcp_metrics["tcp_max_rtt"] = 0
                tcp_metrics["tcp_avg_rtt"] = 0
                if verbose:
                    print("No RTT information available in TCP packets.") 
        else:
            tcp_metrics["tcp_count"] = 0
            tcp_metrics["tcp_retransmissions"] = 0
            tcp_metrics["tcp_duplicate_acks"] = 0
            tcp_metrics["tcp_fast_retransmissions"] = 0
            tcp_metrics["tcp_retransmission_percentage"] = 0
            tcp_metrics["tcp_min_rtt"] = 0
            tcp_metrics["tcp_max_rtt"] = 0
            tcp_metrics["tcp_avg_rtt"] = 0
            if verbose:
                print("No TCP packets found for loss analysis.")
            
    return tcp_metrics

def calculate_udp_metrics(all_packets, verbose = False):
    udp_metrics = {}
    
    udp_packets = [p for p in all_packets if hasattr(p, 'udp')]
    udp_metrics["udp_count"] = len(udp_packets)
    udp_size_metrics = calculate_packet_size_metrics(packets = udp_packets, prefix = "udp", id = None, capture_file_path = None, verbose=False)
    udp_metrics.update(udp_size_metrics)
    if udp_packets:
        if verbose:
            print(f"UDP packets: {len(udp_packets)}")

        # UDP doesn't have built-in loss detection, but you can look for 
        # sequence gaps if the protocol over UDP has sequence numbers
        # For UDP packets (if applicable)

        # Try to detect UDP packet loss for common protocols
        # 1. Look for RTP (Real-time Transport Protocol)
        rtp_packets = [p for p in udp_packets if hasattr(p, 'rtp')]
        udp_metrics["rtp_count"] = len(rtp_packets)

        if rtp_packets and len(rtp_packets) > 1:
            if verbose:
                print(f"Found {len(rtp_packets)} RTP packets")
            
            # Extract sequence numbers
            rtp_seq_nums = [int(p.rtp.seq) for p in rtp_packets if hasattr(p.rtp, 'seq')]
            udp_metrics["rtp_sequence_numbers"] = rtp_seq_nums
            
            # Sort sequence numbers
            rtp_seq_nums.sort()
            
            # Count gaps in sequence
            if rtp_seq_nums:
                expected_packets = rtp_seq_nums[-1] - rtp_seq_nums[0] + 1
                missing_packets = expected_packets - len(rtp_seq_nums)
                udp_metrics["rtp_missing_packets"] = missing_packets
                
                if missing_packets > 0:
                    loss_percentage = (missing_packets / expected_packets) * 100
                    if verbose:
                        print(f"Detected {missing_packets} missing RTP packets ({loss_percentage:.2f}% loss)")
                    udp_metrics["rtp_missing_packets_percentage"] = loss_percentage
                    
                else:
                    udp_metrics["rtp_missing_packets_percentage"] = 0
                    if verbose:
                        print("No RTP packet loss detected")
        
        # 2. Look for DNS queries and responses
        dns_packets = [p for p in udp_packets if hasattr(p, 'dns')]
        
        if dns_packets:
            udp_metrics["dns_count"] = len(dns_packets)
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
                udp_metrics["dns_incomplete_transactions"] = len(incomplete)
                if verbose:
                    print(f"Found {len(incomplete)} DNS queries without responses (potential packet loss)")
            else: 
                udp_metrics["dns_incomplete_transactions"] = 0
                if verbose:
                    print(f"No incomplete DNS transactions detected")
        else: 
            udp_metrics["dns_count"] = 0
            udp_metrics["dns_incomplete_transactions"] = 0
            if verbose:
                print("No DNS packets captured.")
    return udp_metrics

def calculate_ip_metrics(all_packets, verbose = False):
    """
    Analyze IP packets for packet loss and other metrics.
    """
    ip_metrics = {}
    ip_packets = [p for p in all_packets if hasattr(p, 'ip')]
    ip_size_metrics = calculate_packet_size_metrics(packets = ip_packets, prefix = "ip", id = None, capture_file_path = None, verbose=False)
    ip_metrics.update(ip_size_metrics)
    
    if ip_packets:
        # Look for IP fragmentation
        fragmented_packets = [p for p in ip_packets if hasattr(p.ip, 'fragment')]
        fragmented_count = len(fragmented_packets)
        
        # Calculate packet loss percentage
        total_ip = len(ip_packets)
        if total_ip > 0:
            fragmentation_percentage = (fragmented_count / total_ip) * 100
            if verbose:
                print(f"IP packets: {total_ip}")
                print(f"Fragmented IP packets: {fragmented_count} ({fragmentation_percentage:.2f}%)")
            
            ip_metrics["ip_count"] = total_ip
            ip_metrics["ip_fragmented"] = fragmented_count
            ip_metrics["ip_fragmentation_percentage"] = fragmentation_percentage
            
        else:
            ip_metrics["ip_count"] = 0
            ip_metrics["ip_fragmented"] = 0
            ip_metrics["ip_fragmentation_percentage"] = 0
            if verbose:
                print("No IP packets found for fragmentation analysis.")
    return ip_metrics

def calculate_dns_metrics(all_packets, verbose=False):
    """
    Analyze DNS packets for metrics such as query types, response codes, and incomplete transactions.
    """
    dns_metrics = {}
    dns_packets = [p for p in all_packets if hasattr(p, 'dns')]

    if dns_packets:
        dns_metrics["dns_count"] = len(dns_packets)
        if verbose:
            print(f"DNS packets: {len(dns_packets)}")

        # Analyze DNS query types
        query_types = {}
        response_codes = {}
        incomplete_transactions = 0
        transaction_ids = {}

        for packet in dns_packets:
            if hasattr(packet.dns, 'qry_type'):
                qry_type = packet.dns.qry_type
                query_types[qry_type] = query_types.get(qry_type, 0) + 1

            if hasattr(packet.dns, 'flags_response') and packet.dns.flags_response == '1':
                if hasattr(packet.dns, 'resp_code'):
                    resp_code = packet.dns.resp_code
                    response_codes[resp_code] = response_codes.get(resp_code, 0) + 1

            if hasattr(packet.dns, 'id'):
                trans_id = packet.dns.id
                if trans_id in transaction_ids:
                    transaction_ids[trans_id] += 1
                else:
                    transaction_ids[trans_id] = 1

        # Count incomplete transactions
        incomplete_transactions = sum(1 for count in transaction_ids.values() if count == 1)

        dns_metrics["dns_query_types"] = str(query_types)
        dns_metrics["dns_response_codes"] = str(response_codes)
        dns_metrics["dns_incomplete_transactions"] = incomplete_transactions

        if verbose:
            print(f"DNS query types: {query_types}")
            print(f"DNS response codes: {response_codes}")
            print(f"Incomplete DNS transactions: {incomplete_transactions}")
    else:
        dns_metrics["dns_count"] = 0
        dns_metrics["dns_query_types"] = "{}"
        dns_metrics["dns_response_codes"] = "{}"
        dns_metrics["dns_incomplete_transactions"] = 0
        if verbose:
            print("No DNS packets found.")

    return dns_metrics

def calculate_data_metrics(all_packets, verbose = False):
    data_metrics = {}
    data_packets = [p for p in all_packets if hasattr(p, 'data')]

    if data_packets:
        data_metrics["data_count"] = len(data_packets)
        if verbose:
            print(f"DATA packets: {len(data_packets)}")

        # Analyze payload sizes
        payload_sizes = []
        for packet in data_packets:
            if hasattr(packet.data, 'data_len'):
                payload_sizes.append(int(packet.data.data_len))

        if payload_sizes:
            total_payload_size = sum(payload_sizes)
            min_payload_size = min(payload_sizes)
            max_payload_size = max(payload_sizes)
            avg_payload_size = total_payload_size / len(payload_sizes)

            data_metrics["data_total_payload_size"] = total_payload_size
            data_metrics["data_min_payload_size"] = min_payload_size
            data_metrics["data_max_payload_size"] = max_payload_size
            data_metrics["data_avg_payload_size"] = avg_payload_size

            if verbose:
                print(f"DATA payload sizes - Total: {total_payload_size} bytes, Min: {min_payload_size} bytes, Max: {max_payload_size} bytes, Average: {avg_payload_size:.2f} bytes")
        else:
            data_metrics["data_total_payload_size"] = 0
            data_metrics["data_min_payload_size"] = 0
            data_metrics["data_max_payload_size"] = 0
            data_metrics["data_avg_payload_size"] = 0
            if verbose:
                print("No payload size information available in DATA packets.")
    else:
        data_metrics["data_count"] = 0
        data_metrics["data_total_payload_size"] = 0
        data_metrics["data_min_payload_size"] = 0
        data_metrics["data_max_payload_size"] = 0
        data_metrics["data_avg_payload_size"] = 0
        if verbose:
            print("No DATA packets found.")

    return data_metrics

def run_per_layer_analysis(packets, id = None, capture_file_path = None, print_out_packets = False, verbose = False):
    metrics = {}
    
    # Calculate the number of packets per layer
    layer_counts = {}
    for packet in packets:
        for layer in packet.layers:
            layer_name = layer.layer_name
            if layer_name in layer_counts:
                layer_counts[layer_name] += 1
            else:
                layer_counts[layer_name] = 1
    if verbose:
        print(f"Packets per layer: {layer_counts}")
    metrics["layer_counts"] = str(layer_counts)

    try:
        # All packet sizes
        packet_size_metrics = calculate_packet_size_metrics(packets = packets,prefix = "all", id = id, capture_file_path= capture_file_path, print_out_packets = print_out_packets, verbose=verbose)
        metrics.update(packet_size_metrics)
    except Exception as e:
        print(f"Error calculating packet size metrics: {e}")
    try:
        # TCP layer packets
        tcp_metrics = calculate_tcp_metrics(packets, verbose=verbose)
        metrics.update(tcp_metrics)
    except Exception as e:
        print(f"Error calculating TCP metrics: {e}")
    try:
        # UDP layer packets
        udp_metrics = calculate_udp_metrics(packets, verbose=verbose)
        metrics.update(udp_metrics)
    except Exception as e:
        print(f"Error calculating UDP metrics: {e}")
    try: 
        # IP layer packets
        ip_metrics = calculate_ip_metrics(packets, verbose=verbose)
        metrics.update(ip_metrics)
    except Exception as e:
        print(f"Error calculating IP metrics: {e}")
    try: 
        # DNS layer packets
        dns_metrics = calculate_dns_metrics(packets, verbose=verbose)
        metrics.update(dns_metrics)
    except Exception as e:
        print(f"Error calculating DNS metrics: {e}")
    try: 
        # DATA layer packets
        data_metrics = calculate_data_metrics(packets, verbose=verbose)
        metrics.update(data_metrics)
    except Exception as e:
        print(f"Error calculating DATA metrics: {e}")
    return metrics 

##################################### Packet Filters ################################

def get_website_ip(website):
    """Get the IP address of a website using DNS resolution.
    
    Args:
        website (str): The domain name to resolve (e.g., 'google.com')
        
    Returns:
        tuple: (success, ip_address or error_message)
    """
    try:
        # Remove any http/https prefix if present
        clean_website = website.replace('http://', '').replace('https://', '').strip("/")
        
        # Get all IP addresses associated with the domain
        ip_addresses = socket.gethostbyname_ex(clean_website)
        
        # The result is a tuple: (hostname, aliaslist, ipaddrlist)
        primary_ip = ip_addresses[2][0]  # First IP in the list
        all_ips = ip_addresses[2]        # All IPs as a list
        
        # Return the primary IP and all IPs
        return True, (primary_ip, all_ips)
    except socket.gaierror as e:
        error_msg = f"❌ Could not resolve {website}: {e}"
        print(error_msg)
        return False, error_msg
    except Exception as e:
        error_msg = f"❌ Error resolving {website}: {e}"
        print(error_msg)
        return False, error_msg

def filter_packets_by_ip(capture_file, website, verbose = False):
        
    try:
        success, result = get_website_ip(website)
        if success:
            ip_address, _ = result
    
            # Load all packets from the capture file
            packets = pyshark.FileCapture(capture_file)
            
            # Filter packets by IP if provided
            filtered_packets = []
            
            for packet in packets:
                # Skip non-IP packets
                if not hasattr(packet, 'ip'):
                    continue
                    
                # Check if packet is to/from our target IP
                if ip_address and (packet.ip.src == ip_address or packet.ip.dst == ip_address):
                    filtered_packets.append(packet)
            
            # Count packets
            packet_count = len(filtered_packets)
            if verbose:
                print(f"Found {packet_count} packets related to {website} ({ip_address})")
        
            packets.close()
            return filtered_packets
        else:
            print(f"Failed to resolve IP address for {website}. No packets will be filtered.")
            return []
    except Exception as e:
        print(f"Error processing packets: {e}")
        return []


##################################### Main Wrapper Functions ################################
def set_up(record_frag=False, tcp_frag=False, frag_size=20, setting = "baseline"):

    if setting == "proxy_baseline":
        print(f"Setting up proxy baseline with no fragmentation.")
        base_command = f"nohup python3 main.py --no-record_frag --no-tcp_frag"
    
    else: 
        base_command = f"nohup python3 main.py --frag_size {frag_size}"
        if record_frag:
            base_command += " --record_frag"
        if tcp_frag:
            base_command += " --tcp_frag"

    base_command += " --port 4433 &"
    print(f"Running {base_command}")
    os.system(base_command)
    return 

def make_results_folders(setting, website, param_log_string = ""): 
     # Define folder structure for saving results
    label = setting

    # Create result saving folder
    website_base = website.replace("https://", "").replace("http://", "").replace("www", "").replace(".", "_").replace("/", "__")
   
    folder_name = os.path.join(os.getcwd(), "results_new", f"{label}", param_log_string, website_base)
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)
    return folder_name


def run_all_packet_analyses_and_save_to_csv(capture_file, result_folder, param_log_string, website, id, verbose=False): 
        print(f"Starting packet analysis for file {capture_file}...")
        
        # Check if file exists before analyzing
        if os.path.exists(capture_file):
            
            ## Read Packets
            all_packets = pyshark.FileCapture(capture_file)
            all_packets_list = list(all_packets) 
            try: 
                website_packets = filter_packets_by_ip(capture_file, website, verbose)
                website_packets_list = list(website_packets)  

                subsets_to_run = {
                    "all": all_packets_list,
                    "website_only": website_packets_list,
                }
            except Exception as e:
                print(f"Error filtering packets by IP: {e}")
                subsets_to_run = {
                    "all": all_packets_list,
                }

            for subset_name, subset_packets in subsets_to_run.items():
                if verbose:
                    print(f"Running analysis for {subset_name} packets.")
             
                metrics = {}
                metrics["website"] = website
                metrics["id"] = id
                metrics["date"] = time.strftime("%Y-%m-%d %H:%M:%S")
           
                ## Run analysis and update metrics dictionary
                all_packet_metrics = run_per_layer_analysis(subset_packets, id=id, capture_file_path=capture_file, print_out_packets=True, verbose=verbose)
                metrics.update(all_packet_metrics)

                for x in metrics:
                    if verbose:
                        print(f"{x}: {metrics[x]}")
                
                # Save metrics to a CSV file
                metrics_file = os.path.join(result_folder, f"metrics_{subset_name}.csv")
                
                ## Add params + experiment id
                if "__" in param_log_string:
                    param_dict = {key_value.split("=")[0]: key_value.split("=")[1] for key_value in param_log_string.split("__")}
                    for param in param_dict.keys():
                        metrics[f"param_{param}"] = param_dict.get(param, None)
                else: 
                    param_dict = {"param": param_log_string}
                
                metrics["id"] = id

                if os.path.exists(metrics_file):
                    # Append to the existing file (for multiple runs)
                    metrics_df = pd.DataFrame(metrics, index=[0])
                    metrics_df.to_csv(metrics_file, mode='a', header=False, index=False)
                else:
                    # Create a new file
                    metrics_df = pd.DataFrame(metrics, index=[0])
                    metrics_df.to_csv(metrics_file, index=False)
            
                if verbose:
                    print(f"Packet analysis for subset {subset_name} completed.")
                all_packets.close()
        else:
            if verbose:
                print(f"Error: Capture file {capture_file} was not created.")
        
        return  
 
    
def capture_website_traffic_and_write_to_files(website, interface="en0", setting = "basline", id = "", result_folder="results", verbose=False):
    """Capture network traffic while accessing a website."""
    # Create output filenames based on the website name

    try:
        output_file = os.path.abspath(os.path.join(result_folder, "captures", f"{id}_output.txt"))
        capture_file = os.path.abspath(os.path.join(result_folder, "captures", f"{id}_capture.pcap"))
        if not os.path.exists(os.path.join(result_folder, "captures")):
            os.makedirs(os.path.join(result_folder, "captures"), exist_ok=True)
        if verbose:
            print(f"Capture file: {capture_file}")
            print(f"Output file: {output_file}")

        # Create a function for capture to run in a separate thread
        def capture_packets():
            try:
                capture = pyshark.LiveCapture(interface=interface, output_file=capture_file)
                capture.sniff(timeout=40)  # Set a timeout of 30 seconds
                capture.close()
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
        print(f"Waiting 5 seconds for capture thread to start...", flush = True)
        capture_thread.join(timeout=5)  # Wait for the capture thread to start
        time.sleep(5)
        
        # Send the request with curl (following redirects with -L)
        
        if "proxy" in setting:
            if website.startswith("https://") or website.startswith("http://"):
                curl_command = f"curl -L -p -x localhost:4433 -o '{output_file}' -H 'Cache-Control: no-cache' -H 'Pragma: no-cache' -H 'Expires: 0' {website} --connect-timeout 10 --max-time 30"
            else:
                curl_command = f"curl -L -p -x localhost:4433 -o '{output_file}' -H 'Cache-Control: no-cache' -H 'Pragma: no-cache' -H 'Expires: 0' https://{website} --connect-timeout 10 --max-time 30"
        else:
            if website.startswith("https://") or website.startswith("http://"):
                curl_command = f"curl -L -o '{output_file}' -H 'Cache-Control: no-cache' -H 'Pragma: no-cache' -H 'Expires: 0' {website} --connect-timeout 10 --max-time 30"
            else:
                curl_command = f"curl -L -o '{output_file}' -H 'Cache-Control: no-cache' -H 'Pragma: no-cache' -H 'Expires: 0' https://{website} --connect-timeout 10 --max-time 30"
    
        if verbose:
            print(f"Executing: {curl_command}")
        subprocess.run(curl_command, shell=True, check=False)

        time.sleep(5)  # This is important to allow the capture to finish processing between curl calls! 
    
        return capture_file 
    
    except Exception as e:
        print(f"Error processing {website}: {e}")
        return None


##################################### Handle Website Lists ################################
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

def get_website_list(website_list_to_use, sample): 
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
    return websites 


##################################### Main Function ################################

# Example usage:
# python3 test.py --frag_size 20 --tcp_frag --dpyproxy --website_list_to_use test (TCP fragmentation, test website)
# python3 test.py --website_list_to_use censored --sample 10 (Censored websites, sample 10 of them, don't use Dpyproxy)

### Changes for Mininet: 
# Change inference? 
# Change curl command run from h1 or h2 
if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Set up test parameters.")
    parser.add_argument("--frag_size", type=int, default=20, help="Fragment size for the test.")
    parser.add_argument("--tcp_frag", action="store_true", default=False, help="Enable TCP fragmentation.")
    parser.add_argument("--record_frag", action="store_true", default=False, help="Enable recording of fragments.")
    parser.add_argument("--setting", type=str, choices=["dpyproxy", "baseline", "proxy_baseline"], default="baseline", help="Choose the setting to use.")
    parser.add_argument("--website", type=str,  default="wikipedia.org", help="Website to use.")
    parser.add_argument("--sample", type=int, default=0, help="Number of samples to use, if randomly sampling from the list of webistes.")
    parser.add_argument("--verbose", action="store_true", default=False, help="Enable verbose output (all the printouts).")
    
    args = parser.parse_args()

    # Define variables from arguments 
    setting = args.setting
    tcp_frag = args.tcp_frag
    record_frag = args.record_frag
    frag_size = args.frag_size
    website = args.website
    sample = args.sample

    if setting == "dpyproxy" and not (tcp_frag or record_frag):
        print(f"Warning: setting {setting} indicates that you want to run dpyproxy, but no fragmentation options are selected. Setting TCP Fragmentation to True.")
        tcp_frag = True

    interface = "en0"  # Wifi 

    if setting == "dpyproxy": 
        # Set up dpyproxy with actual arguments 
        set_up(record_frag=record_frag, tcp_frag=tcp_frag, frag_size=frag_size)
        param_log_string = f"frag_size={frag_size}__tcp_frag={tcp_frag}__record_frag={record_frag}"
        time.sleep(5)
    elif setting == "proxy_baseline": 
        set_up(record_frag=False, tcp_frag=False, frag_size=0)
        param_log_string = f"proxy_baseline"
        time.sleep(5)
    else: 
        param_log_string = f"dpyproxy=False"
        
    if setting == "dpyproxy":
        print(f"\n{'='*50}\n\033[94m🟣 Processing {website} with dpyproxy enabled ('dpyproxy') \033[0m \n{'='*50}")
    elif setting == "proxy_baseline":
        print(f"\n{'='*50}\n\033[93m🟠 Processing {website} with proxy but no fragementation ('proxy_baseline') \033[0m \n{'='*50}")
    else:
        print(f"\n{'='*50}\n\033[92m🟢 Processing {website} with no proxy ('baseline')\033[0m \n{'='*50}")
    id = str(uuid.uuid4())

    result_folder = make_results_folders(setting, website, param_log_string=param_log_string)

    try:
        capture_file = capture_website_traffic_and_write_to_files(website=website, interface=interface, id=id, setting=setting, result_folder=result_folder, verbose=args.verbose)
        if capture_file is not None:
            run_all_packet_analyses_and_save_to_csv(capture_file, result_folder=result_folder, param_log_string=param_log_string, website=website, id=id, verbose=args.verbose)
        else:
            print(f"Capture file for {website} was not created. Skipping analysis.", flush = True)
    
    except Exception as e:
        print(f"Error processing {website}: {e}", flush = True)
    
    print("Ending thread for prompting and analyzing {website} .".format(website=website))