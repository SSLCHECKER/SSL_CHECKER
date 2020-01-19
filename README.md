# SSL CHECKER

```
 ____ ____  _        ____ _   _ _____ ____ _  _______ ____  
/ ___/ ___|| |      / ___| | | | ____/ ___| |/ / ____|  _ \ 
\___ \___ \| |     | |   | |_| |  _|| |   | ' /|  _| | |_) |
 ___) |__) | |___  | |___|  _  | |__| |___| . \| |___|  _ < 
|____/____/|_____|  \____|_| |_|_____\____|_|\_\_____|_| \_\ 

 Checks the SSL certificate to identify anomolies within its metadata

./sslChecker.sh -h for help

Usage: ./sslChecker.sh [domain, without http/https] or [file]
Flags:

		-h  --help

		-l  --list domains sharing the same certificate of the checked domain. Usage: ./sslChecker.sh domain -l

```

SSL CHECKER is a bash script that was created to assist identifying anomalies within certificates metadata. This may help spotting a malicious activity linked to a certain domain. The script performs analysis on a single given domain or list of domains stored in a file. It has the following features:

- Analysis of the domain’s SSL certificate metadata
- Analysis of the domain using VirusTotal
- Analysis of the domain’s whois record
- Analysis of the domain’s SSL certificate fingerprint (SHA1)

The script performs the following checks:
- If the certificate is expired or not.
- If the certificate has a very long or short age; for example, 10 years or 1 day. According to CA/Browser Forum, two years is the maximum validity period of new SSL certificates, starting on March 1, 2018.
- If the certificate is a self-signed or not.
- If the certificate “Issued to” field and the checked or requested domain match or not. 
- If the domain is listed as part of the “Subject Alternative Domain Name” field or not. 
- If the domain whois record is “redacted” or “private”.
- If the certificate’s fingerprint (SHA1) is listed in https://sslbl.abuse.ch/ database.

My study showed that relying only on analysis of SSL certificate’s metadata with the absence of other data sources in real network traffic such as DNS and other logs, could introduce false positives. Also, detecting malicious activities of domains in encrypted channels is a challenging task. Therefore, other intelligence scanning tools can be added to enhance the detection. The open source tool VirusTotal was added to enhance the analysis of domains. To use VirusTotal, I used the project “VirusTotal CLI”, which is an open source tool that can retrieve information about a file, URL, domain name, IP address, etc from the main source VirusTotal. The tool can be found at https://github.com/VirusTotal/vt-cli page with installation steps. The tool has different releases for different platforms, which are available at https://github.com/VirusTotal/vt-cli/releases. 

- The folder includes a file of whitelisted domains that has top 45 most popular sites based on Alexa.com. This file can be updated to whitelist domains. These domains will go through the SSL certificate metadata check; however, they will not be checked by VirusTotal. 

- If the domain is malicious, and the script spotted anomalies within the certificate’s metadata, the certificate’s fingerprint (SHA1) will be added to a lookup file called “sha1_anomoly_unique.txt” for future checks. The file contains the domain, certificate’s fingerprint (SHA1) and the name of certificate’s issuer.

- If the checked domain redirects to a new domain, the script will perform analysis on both domains. 

- The sslbl.sh script downloads csv file of malicious SSL certificates identified by sslbl.abuse.ch database which is updated on the site every 5 minutes. You need to set a cron job for the script to run every 5 minutes as below:


## Cron job

	*/5 * * * * ~/[PATH]/SSL_CHECKER/sslbl.sh
	
	PATH:where you downloaded the project SSL_CHECKER
	

## Usage

- To use the scripts, first changing the permission is a must for execution:

	`chmod 755 sslChecker.sh ;  chmod 755 sslbl.sh`
	
- To run the script:

	`./sslChecker.sh [domain or a file with list of domains]`
	
- For more information on how to use the script, a help function is provided:

	`./sslChecker.sh -h`
	
- To show list of domains sharing the same certificate. This can help in spotting other malicious domains sharing the same certificate:

	`./sslChecker.sh [domain] -l`

	
	
**Note**: The scaning results might take few long seconds to appear. I'm working to enhance the script for better and fast results  
