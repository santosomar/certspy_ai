# CERT SPY AI
This is a proof-of-concept tool to use AI to use the [certspy](https://github.com/santosomar/certspy) tool to perform automated reconnaissance and analyze the results.

These are examples that are part of Omar's books and video courses related to AI for cybersecurity. 

## What is CertSpy?
[CertSPY](https://github.com/santosomar/certspy) is a Python tool created by Omar Santos (@santosomar) for interfacing with the `crt.sh` API, allowing users to retrieve information on subdomains from digital certificate transparency logs.


## What is Certificate Transparency?
Certificate Transparency (CT) is an open framework aimed at improving the safety of SSL/TLS certificates by creating an open and auditable log of all certificates issued by certificate authorities. It allows for the detection of mistakenly or maliciously issued certificates. In the context of reconnaissance (recon), cybersecurity experts and ethical hackers can utilize CT logs as a rich source of information for mapping the internet landscape. They can extract data about the existence of subdomains of a target domain, revealing potential targets for further investigation or penetration testing. This kind of intel can be vital in identifying vulnerable endpoints, tracking the issuance of new certificates, and generally maintaining a strong security posture against potential cyber threats. The tool crafted in the script leverages CT logs accessible through the crt.sh platform to facilitate such recon efforts, aiding in the timely identification of potential security vulnerabilities.

## AI Recon Script (ai_recon.py)

The `ai_recon.py` script is a powerful tool for performing OSINT (Open Source Intelligence) analysis on a given domain. It combines certificate information gathering, DNS resolution, WHOIS lookups, and AI-powered analysis to provide comprehensive insights about a domain and its associated infrastructure.

### Key Features

1. **Certificate Information Retrieval**: Uses the CertSpy API to gather SSL/TLS certificate information for the specified domain.

2. **DNS Resolution**: Resolves hostnames found in certificate information to their corresponding IP addresses.

3. **WHOIS Lookup**: Performs WHOIS lookups on resolved IP addresses to obtain organization and CIDR information.

4. **AI-Powered Analysis**: Utilizes a language model (like GPT) to analyze the gathered information and provide insights.

### How It Works

1. The script takes a domain name as input.
2. It retrieves SSL/TLS certificate information for the domain.
3. For each hostname found in the certificate:
   - Performs DNS resolution to get the IP address
   - Conducts a WHOIS lookup on the IP address
4. All gathered information is printed to the console in real-time.
5. The collected data is then sent to an AI model for analysis.
6. The AI-generated insights are displayed as the final output.

### Usage

To use the `ai_recon.py` script, run it from the command line with a domain name as an argument:

```bash
python ai_recon.py secretcorp.org
```
You can also use the `ai_recon_md.py` script to generate a markdown file with the results:
```bash
python ai_recon_md.py secretcorp.org -o results.md
```
The output will be saved to the `results.md` file. I have also included an example of the [results.md](results.md) file.

## License
Read the [LICENSE file](LICENSE).

This will start the process of gathering certificate information, resolving hostnames, performing WHOIS lookups, and analyzing the results using AI.

### Requirements

- Python 3.7 or later
- Install the requirements:
```bash
pip3 install -r requirements.txt
```

