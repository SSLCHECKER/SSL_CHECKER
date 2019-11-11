# SSL_CHECKER

SSL CHECKER is a bash script that was created to assist identifying whether a certain domain is malicious or benign based on analysis of SSL certificate’s metadata with other checks. The script performs analysis on a single given domain or list of domains in a file. It performs the following checks:

- Analysis of domain’s SSL certificate metadata
- Analysis of a domain using VirusTotal
- Analysis of domain’s whois record
- Analysis of domain’s SSL certificate fingerprint (SHA1)

The script performs the following checks:
- If the certificate is expired or not.
- If the certificate has a very long or short age; for example, 10 years or 1 day.
- If the certificate is a self-signed certificate or not.
- If the certificate “Issued to/ Subject” fields and domain name match or not. 
- If the domain is listed as part of the “Subject Alternative Domain Name” field or not. 
- If the domain whois record is “redacted” or “private”.


Our study showed that relying on analysis of SSL certificate’s metadata with the absence of other data sources in real network traffic such as DNS and other logs, could introduce false positives. Therefore, checking the domain via the open source tool VirusTotal was added to enhance the validation and checking process. The tool is called “VirusTotal CLI”, which is an open source tool that can retrieve information about a file, URL, domain name, IP address, etc from the main source VirusTotal. The tool can be found at “” page with installation steps. The tool has different releases for different platforms, which are available at “”. 


- If the domain is malicious, the certificate’s fingerprint (SHA1) will be added to a lookup file called “sha1_sslbl_unique.txt” for future checks. 

- We use a file of whitelisted domains that has top 45 most popular sites based on Alexa.com. This file can be updated to whitelist domains.

## Usage

- To use the script, first changing the permission is a must for execution:
	- Chmod 755 sslChecker.sh
- To run the script:
	- ./sslChecker.sh [domain or a file with list of domains]
- For more information on how to use the script, a help function is provided:
	- ./sslChecker.sh -h 
