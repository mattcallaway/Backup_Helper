import os
import shutil
import hashlib
import json
from collections import defaultdict
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import time

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[
    logging.FileHandler("process_log.txt", encoding='utf-8'),
    logging.StreamHandler()
])

# Define your source and backup directories
categories = {
    'Movies': [r"D:\Movies", r"G:\Movies", r"H:\Movies", r"J:\Movies"],
    'TV': [r"D:\TV", r"G:\TV", r"H:\TV", r"J:\TV"],
    'Nia Videos': [r"D:\Nia Videos"],
    'Concerts': [r"D:\Concerts", r"H:\Concerts"],
    'Comedy': [r"H:\Comedy"],
    'Audiobooks': [r"D:\Audiobooks", r"H:\Audiobooks"]
}

backup_categories = {
    'Movies': [r"J:\Backup\Movies", r"I:\Movies", r"K:\Movies"],
    'TV': [r"J:\Backup\TV", r"I:\TV", r"K:\TV"],
    'Nia Videos': [r"K:\Nia Videos"],
    'Concerts': [r"J:\Backup\Concerts", r"I:\Concerts"],
    'Comedy': [r"J:\Backup\Comedy", r"I:\Comedy"],
    'Audiobooks': [r"J:\Backup\Audiobooks", r"I:\Audiobooks"]
}

# Output file paths
output_file_path = r"C:\Users\mattc\Desktop\backup_report.txt"
unbackedup_files_path = r"C:\Users\mattc\Desktop\unbackedup_files.txt"
backup_log_path = r"C:\Users\mattc\Desktop\backup_log.txt"
hash_store_path = r"C:\Users\mattc\Desktop\file_hashes.json"

# Extensions to ignore
IGNORE_EXTENSIONS = {'.jpg', '.nfo', '.srt', '.txt', '.png', 'srr', '.sub', '.idx'}

def get_user_input(prompt, default):
    user_input = input(f"{prompt} [{default}]: ").strip()
    return type(default)(user_input) if user_input else default

def load_hashes():
    if os.path.exists(hash_store_path):
        with open(hash_store_path, 'r', encoding='utf-8') as f:
            logging.debug(f"Loaded hashes from {hash_store_path}")
            return json.load(f)
    return {}

def save_hashes(hash_store):
    with open(hash_store_path, 'w', encoding='utf-8') as f:
        json.dump(hash_store, f, indent=4)
    logging.debug(f"Saved hashes to {hash_store_path}")

def partial_file_hash(file_path, block_size=65536, partial_read_size=20*1024*1024, throttle_sleep=0.01):
    hash_alg = hashlib.sha256()
    file_size = os.path.getsize(file_path)

    with open(file_path, 'rb', buffering=block_size) as f:
        if file_size <= 2 * partial_read_size:
            while chunk := f.read(block_size):
                hash_alg.update(chunk)
        else:
            hash_alg.update(f.read(partial_read_size))
            f.seek(-partial_read_size, os.SEEK_END)
            hash_alg.update(f.read(partial_read_size))
    
    # Throttle to reduce drive wear and tear
    time.sleep(throttle_sleep)

    return hash_alg.hexdigest()

def scan_directory(directory, hash_store, pbar, throttle_sleep, max_workers):
    logging.info(f"Scanning directory: {directory}")
    if not os.path.exists(directory):
        logging.error(f"Directory does not exist: {directory}")
        return defaultdict(list)
    
    files = defaultdict(list)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_file = {executor.submit(partial_file_hash, os.path.join(root, filename), throttle_sleep=throttle_sleep): (root, filename) 
                          for root, _, filenames in os.walk(directory) for filename in filenames 
                          if os.path.splitext(filename)[1] not in IGNORE_EXTENSIONS}
        
        for future in as_completed(future_to_file):
            root, filename = future_to_file[future]
            file_path = os.path.join(root, filename)
            try:
                file_hash = future.result()
                if file_hash:
                    files[file_hash].append(file_path)
                    hash_store[file_path] = file_hash
            except Exception as exc:
                logging.error(f'{file_path} generated an exception: {exc}')
            pbar.update(1)
            pbar.set_postfix({"scanned": pbar.n})
    logging.info(f"Finished scanning directory: {directory}")
    return files

def scan_directories(directories, hash_store, throttle_sleep, max_workers):
    all_files = defaultdict(list)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        overall_pbar = tqdm(total=len(directories), desc="Overall progress", unit="directory")
        
        future_to_dir = {executor.submit(scan_directory, directory, hash_store, tqdm(total=0, desc=f"Scanning {directory}", unit="file", leave=False), throttle_sleep, max_workers): directory 
                         for category, dirs in directories.items() for directory in dirs}
        
        for future in as_completed(future_to_dir):
            directory = future_to_dir[future]
            try:
                files = future.result()
                for file_hash, file_paths in files.items():
                    all_files[file_hash].extend(file_paths)
            except Exception as exc:
                logging.error(f'{directory} generated an exception: {exc}')
            overall_pbar.update(1)
        
        overall_pbar.close()
    return all_files

def compare_files(source_files, backup_files_dict):
    logging.info("Comparing source and backup files...")
    unique_files = defaultdict(list)

    for file_hash, source_paths in source_files.items():
        backup_paths = backup_files_dict.get(file_hash, [])
        if not backup_paths:
            unique_files[file_hash] = source_paths

    logging.info(f"Found {len(unique_files)} unique files.")
    return unique_files

def backup_files(unique_files, categories, backup_categories, throttle_sleep, batch_size, max_files):
    logging.info("Starting backup process...")
    total_size = sum(os.path.getsize(file_path) for paths in unique_files.values() for file_path in paths)
    logging.info(f"Total size of unique files: {total_size / (1024 * 1024):.2f} MB")

    files_backed_up = 0
    with tqdm(total=total_size, unit="B", unit_scale=True, desc="Backing up files") as pbar:
        batch = []
        for file_hash, file_paths in unique_files.items():
            if files_backed_up >= max_files:
                break
            for file_path in file_paths:
                if files_backed_up >= max_files:
                    break
                category = next((cat for cat, dirs in categories.items() if any(file_path.startswith(dir) for dir in dirs)), None)
                if not category:
                    logging.warning(f"No suitable category found for: {file_path}")
                    continue
                
                for backup_dir in backup_categories[category]:
                    if not os.path.exists(backup_dir):
                        logging.error(f"Backup directory does not exist: {backup_dir}")
                        continue
                    
                    backup_path = os.path.join(backup_dir, os.path.relpath(file_path, start=next(dir for dir in categories[category] if file_path.startswith(dir))))
                    backup_folder = os.path.dirname(backup_path)
                    
                    if not os.path.exists(backup_folder):
                        os.makedirs(backup_folder)
                    
                    try:
                        shutil.copy2(file_path, backup_path)
                        logging.info(f"Backed up {file_path} to {backup_path}")
                        pbar.update(os.path.getsize(file_path))
                        batch.append(file_path)
                        files_backed_up += 1
                        break
                    except Exception as e:
                        logging.error(f"Failed to backup {file_path} to {backup_path}: {e}")
                
                if len(batch) >= batch_size:
                    logging.info(f"Processed batch of {len(batch)} files.")
                    batch = []
                    time.sleep(throttle_sleep * 5)  # Longer sleep between batches
    
    if batch:
        logging.info(f"Processed final batch of {len(batch)} files.")

def main():
    # Default values
    default_throttle_sleep_source = 0.01
    default_throttle_sleep_backup = 0.02
    default_throttle_sleep_copy = 0.1
    default_max_workers_source = 2
    default_max_workers_backup = 2
    default_batch_size = 10
    default_max_files = float('inf')

    # Get user inputs for parameters
    throttle_sleep_source = get_user_input("Enter sleep interval between file reads for source drives (seconds)", default_throttle_sleep_source)
    throttle_sleep_backup = get_user_input("Enter sleep interval between file reads for backup drives (seconds)", default_throttle_sleep_backup)
    throttle_sleep_copy = get_user_input("Enter sleep interval between file copy operations (seconds)", default_throttle_sleep_copy)
    max_workers_source = get_user_input("Enter number of concurrent workers for source drives", default_max_workers_source)
    max_workers_backup = get_user_input("Enter number of concurrent workers for backup drives", default_max_workers_backup)
    batch_size = get_user_input("Enter number of files to process in each batch", default_batch_size)
    max_files = get_user_input("Enter maximum number of files to backup in one run", default_max_files)

    try:
        # Load existing hashes
        logging.info("Loading existing hashes...")
        hash_store = load_hashes()

        # Scan source and backup directories concurrently
        logging.info("Starting scan of source directories...")
        source_files = scan_directories(categories, hash_store, throttle_sleep_source, max_workers_source)
        logging.info("Finished scan of source directories.")

        logging.info("Starting scan of backup directories...")
        backup_files_dict = scan_directories(backup_categories, hash_store, throttle_sleep_backup, max_workers_backup)
        logging.info("Finished scan of backup directories.")

        # Save updated hashes
        logging.info("Saving updated hashes...")
        save_hashes(hash_store)

        # Compare files
        logging.info("Comparing files...")
        unique_files = compare_files(source_files, backup_files_dict)

        # Generate reports
        logging.info("Generating reports...")
        with open(output_file_path, 'w', encoding='utf-8') as report_file:
            report_file.write(f"Total unique files (exist in only one place): {len(unique_files)}\n")
            for file_hash, file_paths in unique_files.items():
                for file_path in file_paths:
                    report_file.write(f"{file_path}\n")

        # Proceed to backup stage here...
        proceed = input("Do you want to proceed with backup? (yes/no): ").strip().lower()
        if proceed == "yes":
            backup_files(unique_files, categories, backup_categories, throttle_sleep_copy, batch_size, max_files)
        else:
            logging.info("Backup aborted by user.")
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
