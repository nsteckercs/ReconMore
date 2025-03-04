# grep "ROOT:" domains.txt | cut -d' ' -f2 | sudo httpx -sc -o responsive-domains.txt≈
import subprocess
import requests
import json
import re
import os
from urllib.parse import urlparse

# Function to run shell commands with verbose output
def run_command(command):
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        # Stream output in real-time
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                print(output.strip())
        # Check for errors
        stderr = process.stderr.read()
        if process.returncode != 0:
            print(f"Error running {command}: {stderr}")
            return None
        return True
    except Exception as e:
        print(f"Exception running {command}: {e}")
        return None

# Function to fetch domains from crt.sh
def fetch_crtsh_domains(domain):
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    print(f"Fetching crt.sh data for {domain}...")
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        with open("crtsh_domains.json", "w") as f:
            json.dump(data, f, indent=4)
        domains = {entry["name_value"].strip().lower() for entry in data if "name_value" in entry}
        print(f"Found {len(domains)} domains from crt.sh")
        return domains
    except Exception as e:
        print(f"Error fetching crt.sh data: {e}")
        return set()

# Function to normalize and filter domains
def normalize_domains(domains):
    normalized = set()
    for domain in domains:
        # Remove wildcards, leading/trailing spaces, and invalid characters
        domain = domain.replace("*.", "").strip().lower()
        # Basic domain validation
        if re.match(r"^[a-z0-9][a-z0-9-]*(\.[a-z0-9][a-z0-9-]*)*$", domain):
            normalized.add(domain)
    return normalized

# Function to extract root domain
def get_root_domain(domain):
    parsed = urlparse(f"http://{domain}")
    parts = parsed.hostname.split(".")
    if len(parts) > 2:
        return ".".join(parts[-2:])
    return domain

# Function to separate root domains and subdomains
def organize_domains(domains, target_domain):
    root_sub_map = {}
    root_domain = get_root_domain(target_domain)
    
    for domain in domains:
        if domain.endswith(root_domain):
            if domain == root_domain:
                root_sub_map[domain] = set()  # Root domain with no subdomains yet
            else:
                # Extract subdomain part (e.g., "sub.example.com" -> "sub.example.com")
                subdomain = domain.replace(f".{root_domain}", "")
                root_key = root_domain
                if root_key not in root_sub_map:
                    root_sub_map[root_key] = set()
                # Add subdomain as-is (e.g., "sub.example.com")
                root_sub_map[root_key].add(subdomain)
    
    return root_sub_map

# Main function
def main():
    # Get target domain from user
    target_domain = input("Enter the target domain (e.g., example.com): ").strip().lower()
    if not target_domain:
        print("No domain provided. Exiting.")
        return

    print(f"Starting reconnaissance for {target_domain}...")

    # Temporary files for tool outputs
    amass_output = "amass_output.txt"
    subfinder_output = "subfinder_output.txt"
    waymore_output = "waymore_urls.txt"  # Updated for Waymore
    gau_output = "gau_output.txt"  # Added for GAU

    # Run AMASS in verbose mode
    print("Running AMASS in verbose mode...")
    run_command(f"amass enum -v -passive -d {target_domain} -o {amass_output}")

    # Run Subfinder without silent mode for verbose output
    print("Running Subfinder...")
    run_command(f"subfinder -d {target_domain} -o {subfinder_output}")

    # Run Waymore with verbose output (corrected syntax)
    print("Running Waymore...")
    run_command(f"waymore -i {target_domain} -oU {waymore_output} -mode U -v")

    # Run GAU to gather URLs
    print("Running GAU...")
    run_command(f"gau {target_domain} > {gau_output}")

    # Fetch crt.sh domains
    crtsh_domains = fetch_crtsh_domains(target_domain)

    # Collect all domains
    all_domains = set()
    
    # Read AMASS output
    if os.path.exists(amass_output):
        with open(amass_output, "r") as f:
            all_domains.update(line.strip() for line in f if line.strip())
        print(f"Loaded {len(all_domains)} domains from AMASS")
    
    # Read Subfinder output
    if os.path.exists(subfinder_output):
        with open(subfinder_output, "r") as f:
            all_domains.update(line.strip() for line in f if line.strip())
        print(f"Total domains after Subfinder: {len(all_domains)}")
    
    # Read Waymore output
    if os.path.exists(waymore_output):
        with open(waymore_output, "r") as f:
            all_domains.update(line.strip() for line in f if line.strip())
        print(f"Total domains after Waymore: {len(all_domains)}")
    
    # Read GAU output
    if os.path.exists(gau_output):
        with open(gau_output, "r") as f:
            all_domains.update(line.strip() for line in f if line.strip())
        print(f"Total domains after GAU: {len(all_domains)}")
    
    # Add crt.sh domains
    all_domains.update(crtsh_domains)
    print(f"Total unique domains after crt.sh: {len(all_domains)}")

    # Normalize and filter domains
    normalized_domains = normalize_domains(all_domains)
    print(f"Total unique normalized domains: {len(normalized_domains)}")

    # Organize into root domains and subdomains
    domain_map = organize_domains(normalized_domains, target_domain)

    # Write to domains.txt
    with open("domains.txt", "w") as f:
        for root, subs in domain_map.items():
            f.write(f"ROOT: {root}\n")
            if subs:
                f.write("SUBS:\n")
                for sub in sorted(subs):
                    f.write(f"{sub}\n")
            f.write("--------\n")

    # Clean up temporary files
    for file in [amass_output, subfinder_output, waymore_output, gau_output]:
        if os.path.exists(file):
            os.remove(file)

    print("Reconnaissance complete. Results saved to domains.txt and crtsh_domains.json.")

if __name__ == "__main__":
    main()
