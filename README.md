# CERT SPY AI
[CertSPY](https://github.com/santosomar/certspy) is a Python tool created by Omar Santos (@santosomar) for interfacing with the `crt.sh` API, allowing users to retrieve information on subdomains from digital certificate transparency logs.

This is a proof-of-concept tool to use AI to use the [certspy](https://github.com/santosomar/certspy) tool to perform automated reconnaissance and analyze the results.

## What is Certificate Transparency?
Certificate Transparency (CT) is an open framework aimed at improving the safety of SSL/TLS certificates by creating an open and auditable log of all certificates issued by certificate authorities. It allows for the detection of mistakenly or maliciously issued certificates. In the context of reconnaissance (recon), cybersecurity experts and ethical hackers can utilize CT logs as a rich source of information for mapping the internet landscape. They can extract data about the existence of subdomains of a target domain, revealing potential targets for further investigation or penetration testing. This kind of intel can be vital in identifying vulnerable endpoints, tracking the issuance of new certificates, and generally maintaining a strong security posture against potential cyber threats. The tool crafted in the script leverages CT logs accessible through the crt.sh platform to facilitate such recon efforts, aiding in the timely identification of potential security vulnerabilities.

