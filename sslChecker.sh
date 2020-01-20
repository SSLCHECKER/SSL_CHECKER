#!/bin/bash


#################################################################################
#Script Name	: SSLCHECKER                                                                                             
#Description	: Checks SSL Certificates of domains
#Date		: June 2019
#Version	: 1.2		                                                                                                                                                                        
#Email         	: 100044870@ku.ac.ae                                          
#################################################################################

RED='\033[1;31m'
YELLOW='\033[1;33m'
WHITE='\033[1;37m'
BLUE='\033[1;34m'
GREEN='\033[1;32m'

echo -e "${YELLOW}
 ____ ____  _        ____ _   _ _____ ____ _  _______ ____  
/ ___/ ___|| |      / ___| | | | ____/ ___| |/ / ____|  _ \ 
\___ \___ \| |     | |   | |_| |  _|| |   | ' /|  _| | |_) |
 ___) |__) | |___  | |___|  _  | |__| |___| . \| |___|  _ < 
|____/____/|_____|  \____|_| |_|_____\____|_|\_\_____|_| \_\ ${WHITE}"
                                                            
                              
echo ""

echo -e " Checks the SSL certificate to identify anomolies within its metadata\n"
echo "./sslChecker.sh -h for help"

echo ""                                                  



main(){

			

	domain=$(echo $1 | grep -P -i "(?=^.{5,254}$)(^(?:(?!\d+\.)[a-za-z0-9_\-]{1,63}\.?)+(?:[a-za-z]{2,})$)" | tr A-Z a-z)
	
#if the checked domain redirects to a new domain, the script will analyze the new domain (F_URL) SSL certificate.

	F_URL=`curl -I -Ls $domain 2>/dev/null | grep "Location:"| tail -n 1 | awk -F "://" '{print $2}' | awk -F "/|:" '{print $1}' | tr A-Z a-z`


	SAN_D=$(echo | openssl s_client -connect $domain:443 -servername $domain 2>/dev/null | openssl x509 -noout -text | grep "Subject Alternative Name" -A2 | grep -Eo "DNS:[-a-zA-Z 0-9.*]*" | cut -c 5-)
	NUM_SAN_D=$(echo | openssl s_client -connect $domain:443 -servername $domain 2>/dev/null | openssl x509 -noout -text | grep "Subject Alternative Name" -A2 | grep -Eo "DNS:[-a-zA-Z 0-9.*]*" | cut -c 5- | wc -l)


	
	SAN_F_URL=$(echo | openssl s_client -connect $F_URL:443 -servername $F_URL 2>/dev/null | openssl x509 -noout -text | grep "Subject Alternative Name" -A2 | grep -Eo "DNS:[-a-zA-Z 0-9.*]*" | cut -c 5-)
	NUM_SAN_F_URL=$(echo | openssl s_client -connect $F_URL:443 -servername $F_URL 2>/dev/null | openssl x509 -noout -text | grep "Subject Alternative Name" -A2 | grep -Eo "DNS:[-a-zA-Z 0-9.*]*" | cut -c 5- | wc -l)



	if [[ -z "$1" ]]; then

		help_f
		exit

	elif [[ "$1" == "-h" ]]; then

		help_f
	
		exit
	
	elif [ -f $1 ]; then
		
		for i in `cat $1`
		do
		
			check $i
		
		done 2>/dev/null
		exit
	

	elif [[ ! -z "$domain" && ! -z "$F_URL" && "$domain" != "$F_URL" && -z "$2" ]] ; then
		
		i=$domain

		check $i 2>/dev/null
		

		echo ""

		echo -e "${GREEN}The redirected URL is" $F_URL${WHITE}

		echo ""


		i=$F_URL

		check $i 2>/dev/null

		exit 

	elif [[ ! -z "$domain" && ! -z "$F_URL" && "$domain" == "$F_URL" && -z "$2" ]] ; then
		

		echo -e "${GREEN}The redirected URL is" $F_URL${WHITE}

		echo ""


		i=$F_URL

		check $i 2>/dev/null

		exit 
	

	elif [[ ! -z "$domain" && -z "$F_URL" && -z "$2" ]]; then

		i=$domain

		check $i 2>/dev/null
		
		exit

	
	elif [[ ! -z "$domain" && ! -z "$F_URL" && "$domain" != "$F_URL" && "$2" == "-l" ]]; then

		echo "---------------------"

    		echo -e "${YELLOW}List of domains/subdomains sharing the same certificate of $domain: ${WHITE}" 

		echo "---------------------"
		


		echo -e "$SAN_D\n"
		
		echo "---------------------"

		echo -e "${YELLOW}Total number of results:${WHITE} $NUM_SAN_D"

		echo "---------------------"

		
		echo ""


		echo "---------------------"

    		echo -e "${YELLOW}List of domains/subdomains sharing the same certificate of $F_URL:${WHITE}" 

		echo "---------------------"
		

		
		echo -e "$SAN_F_URL\n"
		
		echo "---------------------"

		echo -e "${YELLOW}Total number of results:${WHITE} $NUM_SAN_F_URL"

		echo "---------------------"

		exit


	elif [[ ! -z "$F_URL" && "$domain" == "$F_URL" && "$2" == "-l" ]]; then

		
		echo "---------------------"

    		echo -e "${YELLOW}List of domains/subdomains sharing the same certificate of $F_URL:${WHITE}" 

		echo "---------------------"
		

	
		echo -e "$SAN_F_URL\n"
		
		echo "---------------------"

		echo -e "${YELLOW}Total number of results:${WHITE} $NUM_SAN_F_URL"

		echo "---------------------"

		exit

	elif [[  ! -z "$domain" && -z "$F_URL" && "$2" == "-l" ]]; then

		echo "---------------------"

    		echo -e "${YELLOW}List of domains/subdomains sharing the same certificate of $domain:${WHITE}" 

		echo "---------------------"
		
		
		echo -e "$SAN_D\n"
		
		echo "---------------------"

		echo -e "${YELLOW}Total number of results:${WHITE} $NUM_SAN_D"

		echo "---------------------"

		exit


	fi


} 


check(){
unset EXPIRED 
unset MISMATCH 
unset AGED 
unset SHORT_AGE 
unset SELF_SIGNED 
unset ISSUEDTO
unset ISSUE
unset PRIVATE
unset WHITELISTED
unset ALT_NAME

# Connects to a remote server (domain) via port 443 and retrieve the public key of the SSL certificate.
# Extracts the Serial Number field, which is a positive integer number (ID) that uniquely identifies a certificate and is issued by a CA.
# Extracts the Subject Name/ Issued To field, which is the certificate’s common name or the owner of the certificate. 
# Extracts the Country field, which includes the 2-character ISO format of a country code. 
# Extracts the Issuer field, which identifies the entity who has issued and signed the certificate.
# Extracts the Start Date field, which shows when the certificate is issued.
# Extracts the End Date field, which shows when the certificate is issued.
# Extracts the Subject key identifier (SKI) field, which is a SHA1-hash key identifier derived from the public key in the subject field of the certificate.
# Extracts the Authority key identifier (AKI) field, which is a SHA1-hash key identifier derived from the public key in the issuer/ signer of the certificate. 
# Extracts the Protocol field, which shows the SSL/TLS versions are supported by the checked website/ domain. 
# Extracts the Signature Algorithm field, which shows the cryptographic algorithm used to sign the certificate and is located in the last field of the certificate.
# Extracts the Cipher suite that is used to create shared keys between and encrypt information between the client and server.
# Extracts the Key Length which is the number of bits used by the cryptographic algorithm or cipher.
# Extracts the Subject Alternative Name (SAN) field which contains additional subject names if the certificate is shared with other different hostnames. 
# Extracts the "Verify return code" value which is used to check if the certificate is self-signed or not with other identifications.
# Extracts the Fingerprint field which contains a unique identifier or hash sum (MD5, SHA-1 or SHA-256 and others) of the ASN.1 binary (DER) encoded certificates. 


	CERTINFO=$(echo | openssl s_client -connect $i:443 -servername $i 2>/dev/null )
	SERIAL_NUM=$(echo "$CERTINFO" | openssl x509 -noout -serial | awk -F '[=]' '{print $2}' ) 
	ISSUEDT0=$(echo "$CERTINFO" | openssl x509 -noout -subject -nameopt multiline 2>/dev/null | grep commonName | grep -Eo '=.*' | cut -c 3- | tr A-Z a-z )  
        COUNTRY=$(echo "$CERTINFO" | openssl x509 -noout -subject -nameopt multiline 2>/dev/null | grep country | grep -Eo '=.*' | cut -c 3- )  
	ISSUER=$(echo "$CERTINFO" | openssl x509 -noout -issuer -nameopt multiline 2>/dev/null | grep  commonName | grep -Eo '=.*' | cut -c 3- ) 
	STARTDATE=$(echo "$CERTINFO" | openssl x509 -noout -startdate 2>/dev/null | cut -d'=' -f 2 )  
	ENDDATE=$(echo "$CERTINFO" | openssl x509 -noout -enddate 2>/dev/null | cut -d'=' -f 2 )
	SKI=$(echo "$CERTINFO" | openssl x509 -noout -text | grep -A1 'Subject Key Identifier' | grep -Eo '[0-9A-F]{2}(:[0-9A-F]{2}){19}' ) 
	AKI=$(echo "$CERTINFO" | openssl x509 -noout -text | grep -A1 'Authority Key Identifier' | grep -Eo '[0-9A-F]{2}(:[0-9A-F]{2}){19}' ) 
	PROTOCOL=$(echo "$CERTINFO" | grep "Protocol  : " | awk -F ':' '{print $2}' ) 2>/dev/null 	
	SIGNETURE_ALG=$(echo "$CERTINFO" | openssl x509 -noout -text | grep "Signature Algorithm" | cut -d ":" -f2 | uniq ) 
	CIPHER=$(echo "$CERTINFO" | grep "Cipher    : " | tr -s [:space:] | awk -F '[:]' '{print $2}' )
	KEY_LENGTH=$(echo | openssl s_client -connect $i:443 2>/dev/null | openssl x509 -noout -text | grep "Public-Key" | awk -F ':' '{print $2}' ) 
	NUM_ALT_NAMES=$(echo | openssl s_client -connect $i:443 -servername $i 2>/dev/null | openssl x509 -noout -text | grep "Subject Alternative Name" -A2 | grep -Eo "DNS:[-a-zA-Z 0-9.*]*" | cut -c 5- | wc -l ) 
	IS_SELFSIGNED=$(echo "$CERTINFO" | grep 'Verify return code' ) 
	FINGERPRINT=$(echo "$CERTINFO" | openssl x509 -fingerprint | grep -Eo '[0-9A-F]{2}(:[0-9A-F]{2}){19}'| tr --delete : | tr '[:upper:]' '[:lower:]' ) 
		

# Calculates the certificate age based on day, month and year. 

	now_epoch=$( date +%s )
	startday_epoch=$( date -d "$STARTDATE" +%s )
    	expiry_epoch=$( date -d "$ENDDATE" +%s )
    	expiry_days="$(( ($expiry_epoch - $now_epoch) / (3600 * 24) ))"
	CertAge_D="$(( ($expiry_epoch - $startday_epoch) / (3600 *24) ))"
	CertAge_M="$(( $CertAge_D / 30 ))"
	CertAge_Y="$(( $CertAge_D / 365 ))"
	

	
	IP=`host $i | awk '/has address/ {print $4}'`

	echo "------------------------------"

	echo -e "${BLUE}DOMAIN INFORMATION${WHITE}"

	echo "------------------------------"
	echo ""
	
	
	echo -e "${YELLOW}Domain:${WHITE}$i"
	if [[ ! -z $IP ]]; then
 
		echo -e "${YELLOW}IP:${WHITE}$IP"
	else
		echo -e "${YELLOW}IP:${WHITE} Doesn't resolve to an IP"
	fi

	if [[ "$CertAge_D" -eq 0  ]]; then
	
		echo -e "No Certificate found\n"


	else 
	

	echo ""
	echo "-------------------------------------"

	echo -e "${BLUE}CERTIFICATE INFORMATION${WHITE}"

	echo "-------------------------------------"
	echo ""
	
	echo -e "${YELLOW}SERIAL NUMBER:${WHITE} $SERIAL_NUM"
	echo -e "${YELLOW}ISSUED TO/ SUBJECT:${WHITE} $ISSUEDT0"
	echo -e "${YELLOW}Country:${WHITE} $COUNTRY"
	echo -e "${YELLOW}ISSUER:${WHITE} $ISSUER"

	echo -e "${YELLOW}START DATE:${WHITE} $STARTDATE"
	echo -e "${YELLOW}END DATE:${WHITE} $ENDDATE"
	echo -e "${YELLOW}CERT AGE:${WHITE} $CertAge_D DAYS WHICH EQUALS $CertAge_M MONTHS or $CertAge_Y YEARS"
	echo -e "${YELLOW}EXPIRES AFTER  ${WHITE}$expiry_days DAYES"
 	
	echo -e "${YELLOW}AUTHORITY KEY IDENTIFIER:${WHITE} $AKI"
	echo -e "${YELLOW}SUBJECT KEY IDENTIFIER:${WHITE} $SKI"
	
	echo -e "${YELLOW}SIGNETURE ALGORITHM:${WHITE} $SIGNETURE_ALG"
	echo -e "${YELLOW}PROTOCOL:${WHITE}$PROTOCOL"
	echo -e "${YELLOW}CIPHER:${WHITE}$CIPHER"
	echo -e "${YELLOW}KEY LENGTH:${WHITE}$KEY_LENGTH"
	echo -e "${YELLOW}NUMBER OF DOMAINS/SUBDOMAINS SHARING THE SAME CERTIFICATES:${WHITE} $NUM_ALT_NAMES"
	echo -e "${YELLOW}FINGERPRINT:${WHITE} $FINGERPRINT"
	
	echo ""
	echo "---------------------"
	
	echo -e "${BLUE}ANALYSIS${WHITE}"

	echo "---------------------"
	echo ""
	 

# Checks if the SSL certficate fingerprint is found in our sha1_anomoly_unique.txt lookup file.

	if true | grep "$FINGERPRINT" sha1_anomoly_unique.txt >/dev/null; then echo -e "The hash: $FINGERPRINT is listed in our lookup file sha1_anomoly_unique.txt of possible suspicious SSL certificates ${RED}*${WHITE}"; fi


# Check if the SSL certficate fingerprint is found in sslbl.abuse.ch Database which is updated every 5 minutes.

	if true ; grep "$FINGERPRINT" ~/sslblacklist.csv >/dev/null; then 
		
		echo -e "The hash: $FINGERPRINT is listed in sslbl.abuse.ch Database ${RED}*${WHITE}"
		echo "$i : $FINGERPRINT : $ISSUER" >> sha1_anomoly.txt 
		cat sha1_anomoly.txt | sort -u | uniq > sha1_anomoly_unique.txt
		
	else 
		echo "The hash: $FINGERPRINT is not listed in sslbl.abuse.ch Database"
		

	fi


# CHECK_EXPIRED: this field checks wither the certificate is expired or still valid. 

 	CHECK_EXPIRED=$( echo "$CERTINFO" | openssl x509 -noout -checkend 0 )

	if [[ "$CHECK_EXPIRED" == *"will not"* ]]; then

		echo "The certificate is not expired"
	else
			
  		EXPIRED="The certificate is expired ${RED}*${WHITE}"
		echo -e $EXPIRED
	fi


# CertAge_D/_M/_Y: this filed shows the validity of a certificate based on day, month and year. 

	if [[ "$CertAge_Y" -gt 3 ]]; then 

		AGED="The certificate has a very long age; suspicious ${RED}*${WHITE}"

		echo -e $AGED
	elif (( "$CertAge_D" <= 10 )); then

		SHORT_AGE="The certificate has a very short age, maybe for testing or it is suspicious activity ${RED}*${WHITE}"
		echo -e $SHORT_AGE
	else 
		
		echo "The certificate has a normal age (According to CA/Browser Forum, two years is the maximum validity period of new SSL certificates, starting on March 1, 2018)"

	fi


# IS_SELFSIGNED contains a value that confirms a certificate is a self-signed one based on different checks performed on the “Verify return code” value obtained from the SSL certificate.
# Different checks are performed to show if the certificate is valid, not valid, revoked, self-signed, expired, not trusted, rejected and other checks.


	if [[ "$IS_SELFSIGNED" == *"0 (ok)"* ]]; then
	
		echo -e "The certificate is correctly signed by a certificate authority"

	elif [[ "$IS_SELFSIGNED" == *"18 (self signed certificate)"* ]] || [[ $SKI == $AKI ]] || [[-z $AKI ]]; then 

		SELF_SIGNED="The Certificate is Self-signed ${RED}*${WHITE}"
		echo -e $SELF_SIGNED 


	elif [[ "$IS_SELFSIGNED" == *"2 (unable to get issuer certificate)"* ]]; then
		
		ISSUE="The issuer certificate could not be found"
		echo $ISSUE

	elif [[ "$IS_SELFSIGNED" == *"7 (certificate signature failure)"* ]]; then
	
		ISSUE="The signature of the certificate is invalid"
		echo $ISSUE
	
	elif [[ "$IS_SELFSIGNED" == *"9 (certificate is not yet valid)"* ]]; then
	
		ISSUE="The certificate is not yet valid"
		echo $ISSUE

	elif [[ "$IS_SELFSIGNED" == *"19 (self signed certificate in certificate chain)"* ]]; then
	
		ISSUE="The certificate chain could be built up using the untrusted certificates, but the root could not be found locally"
		echo $ISSUE
	
	elif [[ "$IS_SELFSIGNED" == *"20 (unable to get local issuer certificate)"* ]]; then
	
		ISSUE="The issuer certificate of a locally looked up certificate could not be found. This normally means the list of trusted certificates is not complete"
		echo $ISSUE

	elif [[ "$IS_SELFSIGNED" == *"23 (certificate revoked)"* ]]; then
	
		ISSUE="The certificate has been revoked"
		echo $ISSUE

	elif [[ "$IS_SELFSIGNED" == *"24 (invalid CA certificate)"* ]]; then
	
		ISSUE="a CA certificate is invalid"
		echo $ISSUE

	elif [[ "$IS_SELFSIGNED" == *"26 (unsupported certificate purpose)"* ]]; then
	
		ISSUE="The supplied certificate cannot be used for the specified purpose"
		echo $ISSUE

	elif [[ "$IS_SELFSIGNED" == *"27 (certificate not trusted)"* ]]; then
	
		ISSUE="The certificate is not trusted"
		echo $ISSUE

	elif [[ "$IS_SELFSIGNED" == *"28 (certificate rejected)"* ]]; then
	
		ISSUE="The certificate is rejected"
		echo $ISSUE

	elif [[ "$IS_SELFSIGNED" == *"50 (application verification failure)"* ]]; then
	
		ISSUE="Application verification failure"
		echo $ISSUE

	fi
	

# Checks if the domain is listed as a value in the SAN field, if the domain is not listed, then this would indicate a mismatch.

	
  	if [ "$i" != "$ISSUEDTO" ]; then
		

		ALT_NAMES=$(echo "$CERTINFO" | openssl x509 -noout -text 2>/dev/null| grep "Subject Alternative Name" -A2 |grep -Eo "DNS:[-a-zA-Z 0-9.*]*" | cut -c 5- | tr A-Z a-z)
      
			for ALT_NAME in $ALT_NAMES; do

			
          			if [ "$i" == "$ALT_NAME" ]; then
            				ISSUEDTO="${ALT_NAME} (alt)"
					echo "The domain $i is listed as an Alternative Domain Name"

	
				fi
			done
	
		if [ -z "$ISSUEDTO" ]; then
          		ISSUEDTO="-"
          		MISMATCH="Possible name mismatch of $i and ( ISSUED TO ) field. (ISSUED TO) could be a wildcard domain, or $i is not listed as an Alternative Domain Name ${RED}*${WHITE}"
			echo -e $MISMATCH
		fi	
       
	
	fi	
		
      	

# Checks if the domain whois record is “redacted” or “private”

	PRIVATE=`whois_info $i | egrep -wi -m1 -o 'PRIVATE|REDACTED|UNVERIFIED'`
		
	if [[ "$PRIVATE" ]]; then
		
		echo -e "Some fields in Whois record are $PRIVATE ${RED}*${WHITE}"
		
	fi

# Checks if the domain is whitelisted 

	if [ true | WHITELISTED=`grep "$i" whitelist.txt`]; then

		echo "The domain is whitelisted"
	
        	

	elif [[ "$MISMATCH" && "$EXPIRED" ]] || [[ "$MISMATCH" && "$AGED" ]] || [[ "$MISMATCH" && "$SELF_SIGNED" ]] || [[ "$MISMATCH" && "$SHORT_AGE" ]] || [[ "$MISMATCH" && "$PRIVATE" ]]  || [[ "$SELF_SIGNED"  && "$EXPIRED" ]] || [[ "$SELF_SIGNED"  && "$SHORT_AGE" ]] || [[ "$SELF_SIGNED"  && "$AGED" ]] || [[ "$SELF_SIGNED"  && "$PRIVATE" ]] || [[ "$EXPIRED"  && "$SHORT_AGE" ]] || [[ "$EXPIRED" && "$PRIVATE" ]] || [[ "$AGED" && "$PRIVATE" ]] || [[ "$SHORT_AGE" && "$PRIVATE" ]]; then

		
		echo ""
		echo -e "${RED}Detected Anomolies within Certificates Metadata, Requires Further Checks${WHITE}"
		echo "$i : $FINGERPRINT : $ISSUER" >> sha1_anomoly.txt 
		cat sha1_anomoly.txt | sort -u | uniq > sha1_anomoly_unique.txt
		VT_S $i
		
		
			
		
	elif [[ "$EXPIRED" || "$MISMATCH" || "$AGED" || "$SHORT_AGE" || "$SELF_SIGNED" || "$ISSUE" || "$PRIVATE" ]]; then
		echo ""

                echo -e "${RED}Requires Further Checks and Monitoring${WHITE}"
		VT_S $i
		
		echo ""
		

	else

		echo "Nothing Looks Suspicious with the SSL Certificate's Metadata"

		VT_S $i
		echo ""
	fi
	
	fi
	
	


		
}

# Scans the domain in VirusTotal using the open source tool "VirusTotal CLI", source: https://github.com/VirusTotal/vt-cli
VT_S(){	

		echo ""
		echo "--------------------------------"
		echo -e "${BLUE}VIRUSTOTAL RESULTS${WHITE}"
		echo "--------------------------------"	
		echo ""

		


			VT_SCAN_M=`./vt url $i | grep -w -m1 "malicious:" | awk -F ':' '{print $2}'`

			VT_SCAN_S=`./vt url $i | grep -w -m1 "suspicious:" | awk -F ':' '{print $2}'`

			if [ "$VT_SCAN_M" -gt 0 ] || [ "$VT_SCAN_S" -gt 0 ]; then

				echo -e "${RED}VT Observed the Domain in a Malicious Activity${WHITE}"
				whois_info $i
				
			else
				
				echo "Nothing Significant"
			

			fi

}
	



# Provids whois information of the domain 

whois_info(){

	echo ""
	echo "--------------------------------"
        echo -e "${BLUE}WHOIS INFORMATION${WHITE}"
	echo "--------------------------------"
	echo ""
	
	whois $i > whois.txt

	msg=`echo "The Script Could not Provide Domain's Whois Record, Please Check it in the Open Source Whois"`
				echo ""
	
	if true | grep -q 'No match\|Not found\|This TLD has no whois server\|No entries' whois.txt; then
	
		if [[ "$i" == *"www."* ]]; then 
	
#The script will strip "www." for whois check, as the command could not provide whois records for domains with "WWW." 

			w=`echo "$i" | awk -F "www." '{print $2}'`; whois $w > whois.txt

			if true | grep -q 'No match\|Not found\|This TLD has no whois server\|No entries' whois.txt; then

				$msg
				echo ""
	
			else 

				cat whois.txt

			fi
		else

			$msg
			echo ""
		fi

	else

		cat whois.txt
	fi


}



help_f(){

	echo "Usage: ./sslChecker.sh [domain, without http/https] or [file]"

	echo "Flags:

		-h  --help

		-l  --list domains sharing the same certificate of the checked domain. Usage: ./sslChecker.sh domain -l

		"

}     

          

main $1 $2 2>/dev/null



