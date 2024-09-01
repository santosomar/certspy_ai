# ai_scan.py

__author__ = "Omar Santos"
__version__ = "0.1.0"
__license__ = "BSD 3-Clause"
__description__ = "AI-powered SSL/TLS analysis of hosts in the results.md file"
__usage__ = "python3 ai_scan.py"

# Import the necessary libraries
import re
import subprocess
import json
import os
from openai import OpenAI
import nmap
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def extract_hostnames_and_ips(file_path):
    """
    Extracts the hostnames and IPs from the results.md file.

    Args:
        file_path (str): The path to the results.md file.

    Returns:
        list: A list of tuples containing the hostname and IP.
    """
    with open(file_path, 'r') as file:
        content = file.read()
    
    pattern = r'### Hostname: ([\w.-]+)\n- IP: ([\d.]+)'
    matches = re.findall(pattern, content)
    return matches

def run_nmap_scan(ip):
    """
    Runs an Nmap scan on the specified IP address.

    Args:
        ip (str): The IP address to scan.

    Returns:
        str: The scan results.
    """
    nm = nmap.PortScanner()
    nm.scan(ip, '443', arguments='--script ssl-enum-ciphers')
    
    # Convert the scan results to a string
    scan_results = json.dumps(nm[ip], indent=2)
    
    return scan_results

def analyze_with_ai(scan_results):
    """
    Analyzes the Nmap SSL cipher scan results using AI.

    Args:
        scan_results (str): The scan results to analyze.

    Returns:
        str: The analysis results.
    """
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    
    prompt = f"""Analyze the following Nmap SSL cipher scan results and provide insights on the security posture, potential vulnerabilities, and recommendations for improvement:

{scan_results}

Please structure your analysis as follows:
1. Overall Security Posture
2. Identified Vulnerabilities
3. Recommendations for Improvement
"""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a cybersecurity expert specializing in SSL/TLS analysis."},
            {"role": "user", "content": prompt}
        ]
    )
    
    return response.choices[0].message.content

def save_results(hostname, ip, analysis):
    """
    Saves the analysis results to cipher_scan_results.md file.

    Args:
        hostname (str): The hostname of the scanned target.
        ip (str): The IP address of the scanned target.
        analysis (str): The AI-generated analysis of the scan results.
    """
    with open('cipher_scan_results.md', 'a') as f:
        f.write(f"# Analysis for {hostname} ({ip})\n\n")
        f.write(analysis)
        f.write("\n\n" + "="*50 + "\n\n")

def main():
    """
    Main function to execute the script.
    """
    hostnames_and_ips = extract_hostnames_and_ips('results.md')
    
    # Clear the contents of cipher_scan_results.md at the start
    open('cipher_scan_results.md', 'w').close()
    
    for hostname, ip in hostnames_and_ips:
        print(f"Scanning {hostname} ({ip})...")
        scan_results = run_nmap_scan(ip)
        
        print(f"Analyzing results for {hostname}...")
        analysis = analyze_with_ai(scan_results)
        
        save_results(hostname, ip, analysis)
        
        print(f"Analysis for {hostname} ({ip}) saved to cipher_scan_results.md")
        print("="*50 + "\n")

if __name__ == "__main__":
    main()