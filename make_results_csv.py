import os
import pandas as pd

def combine_csvs(directory = "test/dpyproxy/frag_size=20__tcp_frag=True__record_frag=False/", name = ""): 
  
    # List to store DataFrames
    all_traffic_dataframes = []
    website_traffic_dataframes = []

    # Iterate through all files in the directory
    for root, _, files in os.walk(directory):
   
        for file in files:
            if file == "metrics_all.csv":
                file_path = os.path.join(root, file)
                try:
                    df = pd.read_csv(file_path, on_bad_lines='skip')
                except Exception as e:
                    print(f"Error reading {file_path}: {e}")
                all_traffic_dataframes.append(df)
            elif file == "metrics_website_only.csv":
                try:
                    file_path = os.path.join(root, file)
                    df = pd.read_csv(file_path, on_bad_lines='skip')
                    #df = pd.read_csv(file_path)
                except Exception as e:
                    print(f"Error reading {file_path}: {e}")
                    continue
                website_traffic_dataframes.append(df)

    # Combine all DataFrames into one
    all_traffic_combined_df = pd.concat(all_traffic_dataframes, ignore_index=True)
    website_traffic_combined_df = pd.concat(website_traffic_dataframes, ignore_index=True)    

    if name: 
        # Save the combined DataFrame to a new CSV file
        all_traffic_combined_df.to_csv(name + "_all_traffic.csv", index=False)
        website_traffic_combined_df.to_csv(name + "_website_only.csv", index=False)
        print(f"Combined CSV saved as '{name}_all_traffic.csv' and '{name}_website_only.csv'")
    return all_traffic_combined_df, website_traffic_combined_df


if __name__ == "__main__":
    folder = "test" 
    name = "csvs_for_mallory/hong_kong_n20"
    os.makedirs(name)
    for setting in os.listdir(folder):
        setting_path = os.path.join(folder, setting)
        if os.path.isdir(setting_path):
            for param in os.listdir(setting_path):
                param_path = os.path.join(setting_path, param)
                if os.path.isdir(param_path):
                    output_name = f"{name}/{setting}_{param}"
                    print(f"Processing {param_path} and saving as {output_name}")
                    all, website = combine_csvs(directory = param_path, name = output_name)
