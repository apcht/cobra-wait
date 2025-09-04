import json
import os
import requests

URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
CACHE_FILE = "attack_data.json"
LOG_FILE = "attack_changes.log"

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

def _format_ttp_alert(ttp_object):
    """Formats a TTP object into a human-readable string."""
    name = ttp_object.get('name', 'N/A')
    description = ttp_object.get('description', 'No description available.').strip()

    # Truncate description for brevity
    if len(description) > 150:
        description = description[:150] + '...'

    # Extract external reference info safely
    ext_ref = ttp_object.get('external_references', [{}])[0]
    ttp_id = ext_ref.get('external_id', 'N/A')
    ttp_url = ext_ref.get('url', 'URL not available')

    # Filter out objects that are not attack-patterns, intrusions-sets, etc.
    if not ttp_object.get('type', '').startswith(('attack-pattern', 'intrusion-set', 'malware', 'tool')):
        return None

    return (
        f"  - Name: {name}\n"
        f"  - ID: {ttp_id}\n"
        f"  - URL: {ttp_url}\n"
        f"  - Description: {description}"
    )

import datetime

def compare_data(old_data, new_data, log_file):
    """Compares old and new ATT&CK data and prints/logs alerts for changes."""
    old_objects = {obj['id']: obj for obj in old_data.get('objects', []) if obj.get('type') in ['attack-pattern', 'intrusion-set', 'malware', 'tool']}
    new_objects = {obj['id']: obj for obj in new_data.get('objects', []) if obj.get('type') in ['attack-pattern', 'intrusion-set', 'malware', 'tool']}

    new_ttps = []
    updated_ttps = []

    for obj_id, new_obj in new_objects.items():
        if obj_id not in old_objects:
            formatted_alert = _format_ttp_alert(new_obj)
            if formatted_alert:
                new_ttps.append(formatted_alert)
        else:
            old_obj = old_objects[obj_id]
            if new_obj.get('modified') != old_obj.get('modified'):
                formatted_alert = _format_ttp_alert(new_obj)
                if formatted_alert:
                    updated_ttps.append(formatted_alert)

    if not new_ttps and not updated_ttps:
        print("No new or updated TTPs found.")
        return

    log_content = []

    if new_ttps:
        header = "\n[+] Found New TTPs:"
        print(header)
        log_content.append(header)
        for ttp in new_ttps:
            print(ttp + "\n")
            log_content.append(ttp + "\n")

    if updated_ttps:
        header = "\n[*] Found Updated TTPs:"
        print(header)
        log_content.append(header)
        for ttp in updated_ttps:
            print(ttp + "\n")
            log_content.append(ttp + "\n")

    with open(log_file, 'a', encoding='utf-8') as f:
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        f.write(f"\n--- Changes detected at {timestamp} ---\n")
        f.write("\n".join(log_content))
        f.write("\n--- End of report ---\n")
    print(f"Changes have been appended to {log_file}")

def main():
    """Main function to monitor MITRE ATT&CK TTPs."""
    print("Starting ATT&CK TTP monitor...")

    new_data = download_attack_data(URL)
    if not new_data:
        return

    old_data = load_local_cache(CACHE_FILE)

    if old_data:
        compare_data(old_data, new_data, LOG_FILE)
    else:
        print("No local cache found. Creating one...")

    save_local_cache(CACHE_FILE, new_data)
    print("ATT&CK TTP monitor finished.")

if __name__ == "__main__":
    main()
