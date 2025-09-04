import json
import os
import requests

URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
CACHE_FILE = "attack_data.json"

def download_attack_data(url):
    """Downloads the ATT&CK data from the given URL."""
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()  # Raise an exception for bad status codes
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error downloading data: {e}")
        return None

def load_local_cache(filepath):
    """Loads the local cache of ATT&CK data."""
    if not os.path.exists(filepath):
        return None
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_local_cache(filepath, data):
    """Saves the given data to the local cache file."""
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)

def compare_data(old_data, new_data):
    """Compares old and new ATT&CK data and prints alerts for changes."""
    old_objects = {obj['id']: obj for obj in old_data.get('objects', [])}
    new_objects = {obj['id']: obj for obj in new_data.get('objects', [])}

    for obj_id, new_obj in new_objects.items():
        if obj_id not in old_objects:
            print(f"[+] New TTP found: {new_obj.get('name')} ({new_obj.get('external_references', [{}])[0].get('external_id', '')})")
        else:
            old_obj = old_objects[obj_id]
            if new_obj.get('modified') != old_obj.get('modified'):
                print(f"[*] Updated TTP found: {new_obj.get('name')} ({new_obj.get('external_references', [{}])[0].get('external_id', '')})")

def main():
    """Main function to monitor MITRE ATT&CK TTPs."""
    print("Starting ATT&CK TTP monitor...")

    new_data = download_attack_data(URL)
    if not new_data:
        return

    old_data = load_local_cache(CACHE_FILE)

    if old_data:
        compare_data(old_data, new_data)
    else:
        print("No local cache found. Creating one...")

    save_local_cache(CACHE_FILE, new_data)
    print("ATT&CK TTP monitor finished.")

if __name__ == "__main__":
    main()
