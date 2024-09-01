# ai_recon.py

__author__ = "Omar Santos"
__version__ = "0.1.0"
__license__ = "BSD 3-Clause"
__description__ = "AI-powered OSINT Analysis of hosts based on certificate transparency logs"
__usage__ = "python3 ai_recon.py secretcorp.org"

# Import the necessary libraries
from certspy import certspy
from dotenv import load_dotenv
from langchain.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
import os
import argparse
import socket
from ipwhois import IPWhois
import dns.resolver

def load_environment():
    """
    Loads the environment variables from the .env file and returns a ChatOpenAI model.
    """
    load_dotenv()
    return ChatOpenAI(model="gpt-4o-mini")

def create_prompt_template(domain):
    """
    Creates a prompt template for the given domain.

    Args:
        domain (str): The domain to create a prompt template for.

    Returns:
        ChatPromptTemplate: A prompt template for the given domain.
    template = f"""You are an expert security researcher and OSINT investigator specializing in analyzing domain information for {domain}.
    Given the following information about SSL/TLS certificates associated with {domain}, provide an analysis:

    Domain: {domain}
    Certificate Information:
    {{cert_info}}

    Please analyze this information and provide insights on:
    1. The security posture of the domain
    2. Any potential sensitive hosts
    3. Additional reconnaissance steps that could be taken based on this information
    4. Any other relevant observations

    Your analysis:"""
    return ChatPromptTemplate.from_template(template)

def get_certificate_info(domain):
    """
    Retrieves the certificate information for the given domain.

    Args:
        domain (str): The domain to retrieve certificate information for.

    Returns:
        str: A string containing the certificate information.
    api = certspy.certspy()
    results = api.search(domain)
    if results:
        formatted_results = api.format_results(results, common_name_only=True)
        return formatted_results
    return None

def resolve_dns(hostname):
    """
    Resolves the IP address for the given hostname.

    Args:
        hostname (str): The hostname to resolve.

    Returns:
        str: The IP address for the given hostname.
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None

def get_whois_info(ip):
    """
    Retrieves the organization and CIDR information for the given IP address.

    Args:
        ip (str): The IP address to retrieve information for.

    Returns:
        tuple: A tuple containing the organization and CIDR information.
    try:
        obj = IPWhois(ip)
        results = obj.lookup_rdap(depth=1)
        org = results.get('network', {}).get('name')
        cidr = results.get('network', {}).get('cidr')
        return org, cidr
    except Exception:
        return None, None

def analyze_hostnames(cert_info):
    """
    Analyzes the hostnames in the certificate information.

    Args:
        cert_info (list): A list of hostnames in the certificate information.

    Returns:
        str: A string containing the analysis of the hostnames.
    """
    additional_info = []
    for hostname in cert_info:
        ip = resolve_dns(hostname)
        if ip:
            org, cidr = get_whois_info(ip)
            additional_info.append(f"Hostname: {hostname}\nIP: {ip}\nOrganization: {org}\nCIDR: {cidr}\n")
    return "\n".join(additional_info)

def analyze_domain(model, prompt_template, domain, cert_info):
    """
    Analyzes the domain using the AI model and prompt template.

    Args:
        model (ChatOpenAI): The AI model to use for analysis.
        prompt_template (ChatPromptTemplate): The prompt template to use for analysis.
        domain (str): The domain to analyze.
        cert_info (str): The certificate information to use for analysis.
    """
    prompt = prompt_template.invoke({"cert_info": cert_info})
    return model.invoke(prompt)

def parse_arguments():
    """
    This function sets up an argument parser to handle command-line inputs for the AI-powered OSINT Analysis tool.
    It defines a single required argument 'domain' which represents the target domain for analysis.

    Returns:
        argparse.Namespace: An object containing the parsed arguments.
            - domain (str): The domain to analyze.

    Example usage:
        python3 ai_recon.py secretcorp.org
    """
  
    parser = argparse.ArgumentParser(description="AI-powered OSINT Analysis of hosts based on certificate transparency logs")
    parser.add_argument("domain", help="The domain to analyze")
    return parser.parse_args()

def main():
    args = parse_arguments()
    domain = args.domain
    print(f"-----OSINT Analysis of Domain {domain}-----")

    model = load_environment()
    prompt_template = create_prompt_template(domain)
    cert_info = get_certificate_info(domain)

    if cert_info:
        additional_info = analyze_hostnames(cert_info)
        full_info = "\n".join(cert_info) + "\n\nAdditional Information:\n" + additional_info
        result = analyze_domain(model, prompt_template, domain, full_info)
        print(result.content)
    else:
        print(f"No certificate information found for {domain}")

if __name__ == "__main__":
    main()