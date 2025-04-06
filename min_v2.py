import pyshark
import subprocess
import socket
import os
import time
import threading

def capture_website_traffic(website, interface="en0"):
    """Capture network traffic while accessing a website."""
    # Create output filenames based on the website name
    website_base = website.replace(".", "_")
    output_file = f"{website_base}_output.txt"
    capture_file = f"{website_base}_capture.pcap"
    
    try:
        # Resolve the IP address
        website_ip = socket.gethostbyname(website)
        print(f"Resolved IP for {website}: {website_ip}")
        
        # Use absolute path for the capture file
        current_dir = os.path.dirname(os.path.abspath(__file__))
        capture_file_path = os.path.join(current_dir, capture_file)
        
        # Create a function for capture to run in a separate thread
        def capture_packets():
            try:
                capture = pyshark.LiveCapture(interface=interface, output_file=capture_file_path)
                capture.sniff(timeout=15)  # Set a timeout of 15 seconds
                return capture
            except Exception as e:
                print(f"Capture error: {e}")
                return None
        
        # Start capture in a thread 
        print(f"Starting capture for {website}...")
        capture_thread = threading.Thread(target=capture_packets)
        capture_thread.daemon = True
        capture_thread.start()
        
        # Wait a moment for capture to start
        time.sleep(2)
        
        # Send the request with curl (following redirects with -L)
        curl_command = f"curl -L -p -x localhost:4433 -o {output_file} https://{website}"
        print(f"Executing: {curl_command}")
        os.system(curl_command)
        
        # Wait for the capture thread to complete
        time.sleep(5)  # Give time for response to complete
        
        # Check if file exists before analyzing
        if os.path.exists(capture_file_path):
            print(f"Packet capture for {website} saved to {capture_file_path}")
            try:
                filtered_packets = pyshark.FileCapture(capture_file_path)
                packets = list(filtered_packets)  # Force load all packets
                packet_count = len(packets)
                print(f"Captured {packet_count} packets for {website}.")
                
                # Store packet sizes in a list
                packet_sizes = [int(packet.length) for packet in packets if hasattr(packet, 'length')]
                
                # Calculate total packet size
                total_size = sum(packet_sizes)
                print(f"Total size of captured packets: {total_size} bytes.")
                
                # Calculate packet distribution
                if packet_sizes:
                    min_size = min(packet_sizes)
                    max_size = max(packet_sizes)
                    average_size = total_size / len(packet_sizes)
                    print(f"Packet size distribution - Min: {min_size} bytes, Max: {max_size} bytes, Average: {average_size:.2f} bytes.")
                else:
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
                        print(f"TCP packets: {total_tcp}")
                        print(f"Retransmissions: {retrans_count} ({retrans_percentage:.2f}%)")
                        print(f"Duplicate ACKs: {dup_ack_count}")
                        print(f"Fast Retransmissions: {fast_retrans_count}")
                    else:
                        print("No TCP packets found for loss analysis.")
                else:
                    print("No TCP packets captured for loss analysis.")

                # For UDP packets (if applicable)
                udp_packets = [p for p in packets if hasattr(p, 'udp')]
                if udp_packets:
                    print(f"UDP packets: {len(udp_packets)}")
                    # UDP doesn't have built-in loss detection, but you can look for 
                    # sequence gaps if the protocol over UDP has sequence numbers
                    # For UDP packets (if applicable)

                    # Try to detect UDP packet loss for common protocols
                    # 1. Look for RTP (Real-time Transport Protocol)
                    rtp_packets = [p for p in udp_packets if hasattr(p, 'rtp')]
                    if rtp_packets and len(rtp_packets) > 1:
                        print(f"Found {len(rtp_packets)} RTP packets")
                        
                        # Extract sequence numbers
                        rtp_seq_nums = [int(p.rtp.seq) for p in rtp_packets if hasattr(p.rtp, 'seq')]
                        
                        # Sort sequence numbers
                        rtp_seq_nums.sort()
                        
                        # Count gaps in sequence
                        if rtp_seq_nums:
                            expected_packets = rtp_seq_nums[-1] - rtp_seq_nums[0] + 1
                            missing_packets = expected_packets - len(rtp_seq_nums)
                            
                            if missing_packets > 0:
                                loss_percentage = (missing_packets / expected_packets) * 100
                                print(f"Detected {missing_packets} missing RTP packets ({loss_percentage:.2f}% loss)")
                                
                                # Find the specific gaps
                                gaps = []
                                for i in range(len(rtp_seq_nums) - 1):
                                    if rtp_seq_nums[i+1] - rtp_seq_nums[i] > 1:
                                        gaps.append((rtp_seq_nums[i], rtp_seq_nums[i+1]))
                                
                                if gaps:
                                    print("Sequence gaps detected at:", gaps[:5])
                                    if len(gaps) > 5:
                                        print(f"...and {len(gaps) - 5} more gaps")
                            else:
                                print("No RTP packet loss detected")
                    
                    # 2. Look for DNS queries and responses
                    dns_packets = [p for p in udp_packets if hasattr(p, 'dns')]
                    if dns_packets:
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
                            print(f"Found {len(incomplete)} DNS queries without responses (potential packet loss)")
                        else: 
                            print(f"No incomplete DNS transactions detected")
                
                filtered_packets.close()
            except Exception as e:
                print(f"Error analyzing capture file: {e}")
        else:
            print(f"Error: Capture file {capture_file_path} was not created.")
        
        return True
    except Exception as e:
        print(f"Error processing {website}: {e}")
        return False

if __name__ == "__main__":
    # List of websites to analyze
    websites = [
        "wikipedia.org"
    ]
    
    interface = "en0"  # Replace with your network interface
    
    # Process each website
    for website in websites:
        print(f"\n{'='*50}\nProcessing {website}\n{'='*50}")
        capture_website_traffic(website, interface)
        time.sleep(1)  # Small pause between websites
    
    print("\nAll websites processed!")