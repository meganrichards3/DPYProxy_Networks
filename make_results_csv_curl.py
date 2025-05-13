import os
import pandas as pd

def combine_csvs(directory = "test/dpyproxy/frag_size=20__tcp_frag=True__record_frag=False/", name = ""): 
  
    # List to store DataFrames
    curl_dataframes = []

    # Iterate through all files in the directory
    for root, _, files in os.walk(directory):
   
        for file in files:
            if file == "metrics_curl.csv":
                file_path = os.path.join(root, file)
                try:
                    df = pd.read_csv(file_path, on_bad_lines='skip')
                except Exception as e:
                    print(f"Error reading {file_path}: {e}")
                curl_dataframes.append(df)
            

    # Combine all DataFrames into one
    all_curl_combined_df = pd.concat(curl_dataframes, ignore_index=True)
 

    if name: 
        # Save the combined DataFrame to a new CSV file
        
        all_curl_combined_df.to_csv(name + "_curl.csv", index=False)
        print(f"Combined CSV saved as '{name}_curl.csv''")
    return all_curl_combined_df


if __name__ == "__main__":
    folder = "test" 
    name = "csvs_for_mallory/hong_kong_n20"
    os.makedirs(name, exist_ok=True)
    for setting in os.listdir(folder):
        setting_path = os.path.join(folder, setting)
        if os.path.isdir(setting_path):
            for param in os.listdir(setting_path):
                param_path = os.path.join(setting_path, param)
                if os.path.isdir(param_path):
                    output_name = f"{name}/{setting}_{param}"
                    print(f"Processing {param_path} and saving as {output_name}")
                    curl = combine_csvs(directory = param_path, name = output_name)
