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


def make_results_folders(setting, website, param_log_string = ""): 
     # Define folder structure for saving results
    label = setting

    # Create result saving folder
    website_base = website.replace("https://", "").replace("http://", "").replace("www", "").replace(".", "_").replace("/", "__")
   
    folder_name = os.path.join(os.getcwd(), "test", f"{label}", param_log_string, website_base)
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)
    return folder_name

def capture_website_traffic_and_write_to_files(website, interface="en0", setting = "basline", id = "", result_folder="results", verbose=False):
    """Capture network traffic while accessing a website."""

    try:
        output_file = os.path.abspath(os.path.join(result_folder, "captures", f"{id}_output.txt"))
        
        if not os.path.exists(os.path.join(result_folder, "captures")):
            os.makedirs(os.path.join(result_folder, "captures"), exist_ok=True)
        if verbose:
            print(f"Output file: {output_file}")
        
        if "proxy" in setting:
            if website.startswith("https://") or website.startswith("http://"):
                curl_command = [
                    "curl",
                    "-L",
                    "-p",
                    "-x", "localhost:4433",
                    "-o", output_file,
                    "--no-sessionid",
                    "-H", "Cache-Control: no-cache",
                    "-H", "Pragma: no-cache",
                    "-H", "Expires: 0",
                    website,
                    "--connect-timeout", "10",
                    "--max-time", "30",
                    "-w",
                    "DNS: %{time_namelookup}\nConnect: %{time_connect}\nTLS: %{time_appconnect}\nTTFB: %{time_starttransfer}\nTotal: %{time_total}\nRedirect: %{time_redirect}\n",
                ]
            else:
                curl_command = [
                    "curl",
                    "-L",
                    "-p",
                    "-x", "localhost:4433",
                    "-o", output_file,
                    "--no-sessionid",
                    "-H", "Cache-Control: no-cache",
                    "-H", "Pragma: no-cache",
                    "-H", "Expires: 0",
                    f"https://{website}",
                    "--connect-timeout", "10",
                    "--max-time", "30",
                    "-w",
                    "DNS: %{time_namelookup}\nConnect: %{time_connect}\nTLS: %{time_appconnect}\nTTFB: %{time_starttransfer}\nTotal: %{time_total}\nRedirect: %{time_redirect}\n",
                ]
                
        else:
            if website.startswith("https://") or website.startswith("http://"):
                curl_command = [
                    "curl",
                    "-L",
                    "--no-sessionid",
                    "-o", output_file,
                    "-H", "Cache-Control: no-cache, no-store, must-revalidate",
                    "-H", "Pragma: no-cache",
                    "-H", "Expires: 0",
                    website,
                    "--connect-timeout", "10",
                    "--max-time", "30",
                     "-w",
                    "DNS: %{time_namelookup}\nConnect: %{time_connect}\nTLS: %{time_appconnect}\nTTFB: %{time_starttransfer}\nTotal: %{time_total}\nRedirect: %{time_redirect}\n",
                ]
            else: 
                curl_command = [
                    "curl",
                    "-L",
                    "-o", output_file,
                    "--no-sessionid",
                    "-H", "Cache-Control: no-cache, no-store, must-revalidate",
                    "-H", "Pragma: no-cache",
                    "-H", "Expires: 0",
                    f"https://{website}",
                    "--connect-timeout", "10",
                    "--max-time", "30", 
                     "-w",
                    "DNS: %{time_namelookup}\nConnect: %{time_connect}\nTLS: %{time_appconnect}\nTTFB: %{time_starttransfer}\nTotal: %{time_total}\nRedirect: %{time_redirect}\n",
                ]  
    
        if verbose:
            print(f"Executing: {curl_command}")
        result = subprocess.run(curl_command, capture_output=True, text=True)
        output = result.stdout

        # Parse metrics from the output
        metrics = {}
        for line in output.strip().split("\n"):
            if line:
                key, value = line.split(": ")
                metrics[key.strip()] = float(value.strip())

        # Example access
        print("Redirect Time:", metrics.get("Redirect"))
        print("All Metrics:", metrics)
        if os.path.exists(output_file):
            os.remove(output_file)
        return metrics 
    
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
    #interface = "ens4"  # Wifi 

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
        metrics = capture_website_traffic_and_write_to_files(website=website, interface=interface, id=id, setting=setting, result_folder=result_folder, verbose=args.verbose)
        metrics_file = os.path.join(result_folder, f"metrics_curl.csv")
        if os.path.exists(metrics_file):
            # Append to the existing file (for multiple runs)
            metrics_df = pd.DataFrame(metrics, index=[0])
            metrics_df.to_csv(metrics_file, mode='a', header=False, index=False)
        else:
            # Create a new file
            metrics_df = pd.DataFrame(metrics, index=[0])
            metrics_df.to_csv(metrics_file, index=False)
    except Exception as e:
        print(f"Error processing {website}: {e}", flush = True)
    
    print("Ending thread for prompting and analyzing {website} .".format(website=website))