#!/bin/bash

######
#
# Utilizing Openssl and Apache2 to setup our own Certificate Authority, and 
# self-sign certificates to test with.  Client authentication also required.
#
# Command line arguments: -ssl#; -opt#; -h; -v; --sign; --abecert attr1 attr2 attr3  
# -s# = execute a step; -opt# = execute an optional step; -h = help; 
# -v verbose output; --sign for signing a certificate.
#
# Not a sophisticated script, and mostly used for testing purposes.  Note 
# this script can be reconfigured via the global variables (this has been
# tested).  Use this script to help quickly stand-up a test SSL server; or create
# a public certificate for ABE attributes.
#
# Reference material:
#   http://www.tc.umn.edu/~brams006/selfsign.html
#   http://www.debian-administration.org/article/Setting_up_an_SSL_server_with_Apache2
#   http://en.gentoo-wiki.com/wiki/Apache2/SSL_Certificates
#   http://www.symantec.com/connect/articles/apache-2-ssltls-step-step-part-1
#
######

# Tweak as you feel necessary; additional information concerning openssl options.
CMDS="openssl apache2"
export SSLDIR=$HOME/ca
export ABEDIR=$HOME/abe/ca

if [ $# -lt 1 ]; then
	echo "You have not provided any arguments, please execute with -h for help."
	echo "This should be ran as root user!"
	exit -1
elif [ "$1" == "-h" ]; then
	echo "This script executes in steps, and thus requires you to provide the following arguments:"
        echo ""
	echo "./testSSL.sh -ssl#      to execute a step #."
	echo "./testSSL.sh -opt#      to execute an optional step #."
	echo "./testSSL.sh -h         to print this help."
        echo "./testSSL.sh -v         to print verbose. This will echo additional information as the script runs."
	echo "./testSSL.sh --abecert attr1...attN to create a public certificate for ABE attributes."
        echo ""
	echo "----------------------------------------------------------------------------------------------------------------"
        echo "How will SSL work for us? [QuickStart -ssl1 through -ssl4]"
	echo ""
        echo "SSL Client: iHealthEMR Hello: I want to establish a seure connection with the Hospital Server.  I support SSL and some ciphers."
        echo "SSL Server: Hospital Hello  : I accept request; I choose SSL / this cipher suite."
        echo "            Hospital Send   : Server Certificate (opt), Server Public Key (opt, if no certificate), Client Certificate Request" 
	echo "                              to authenticate the iHealthEMR phone application by requesting a signed CA."
        echo "SSL Client: iHealthEMR Send : Client Certificate (to authenticate), Client Key Exchange with more parameters encrypted under"
	echo "                              the servers public key, Certificate Verification by signing some info using private key of client" 
	echo "			            that corresponds to it's certificate."
        echo "[Encrypted] Application Data Client <--> [Encrypted] Application Data Server"
	echo ""
	echo "----------------------------------------------------------------------------------------------------------------"
	echo "How does the ABE certificate work?"
	echo ""
	echo "Much like the SSL process, we will generate our own Certificate Authority and self-sign a phone.crt.  This certificate will"
	echo "use the organization name to store its attributes as a string, to be parsed and verified later."
	echo ""
	exit -1
else
	echo "Running step $1..."
	if [ "$2" == "-v" ]; then
		echo "In verbose mode!"
	fi
fi

# Buffer some space; check for apache2 and openssl.
echo "..."
for i in $CMDS
do
	type -P $i &>/dev/null && continue || { echo "$i command not found."; exit 1; }
done
echo "..."


if [ "$1" == "-ssl1" ]; then
	if [ "$2" == "-v" ]; then
		echo "Making our own CA, and self-signing a server certificate.  Step one, setting up the environment (Directory Structure, and openssl.cnf).  MODIFY openssl.cnf to your specifications prior to step 2 execution!"
                echo "  config - Setup defaulted, satndard configuration information; template can be found in something similar to /etc/ssl/openssl.cnf."
		echo "..."
		echo "Executing: export SSLDIR=$HOME/ca"
		echo "mkdir -p $SSLDIR $SSLDIR/certs $SSLDIR/crl $SSLDIR/newcerts $SSLDIR/private $SSLDIR/requests"  
		echo "touch $SSLDIR/index.txt"
		echo "echo '01' > $SSLDIR/serial"
		echo "chmod 700 $SSLDIR"
	fi
	mkdir -p $SSLDIR $SSLDIR/certs $SSLDIR/crl $SSLDIR/newcerts $SSLDIR/private $SSLDIR/requests
	touch $SSLDIR/index.txt
	echo "01" > $SSLDIR/serial
	chmod 700 $SSLDIR
	echo "# =================================================" > $SSLDIR/openssl.cnf 
	echo "# OpenSSL configuration file " >> $SSLDIR/openssl.cnf
	echo "# ================================================= " >> $SSLDIR/openssl.cnf
	echo "RANDFILE         = $SSLDIR/.rnd " >> $SSLDIR/openssl.cnf
	echo "[ ca ] " >> $SSLDIR/openssl.cnf
	echo "default_ca       = CA_default " >> $SSLDIR/openssl.cnf
	echo "[ CA_default ] " >> $SSLDIR/openssl.cnf
	echo "dir              = $SSLDIR " >> $SSLDIR/openssl.cnf
	echo "certs            = \$dir/certs " >> $SSLDIR/openssl.cnf
	echo "new_certs_dir    = \$dir/newcerts " >> $SSLDIR/openssl.cnf
	echo "crl_dir          = \$dir/crl " >> $SSLDIR/openssl.cnf
	echo "database         = \$dir/index.txt " >> $SSLDIR/openssl.cnf
	echo "private_key      = \$dir/private/ca.key " >> $SSLDIR/openssl.cnf
	echo "certificate      = \$dir/ca.crt " >> $SSLDIR/openssl.cnf
	echo "serial           = \$dir/serial " >> $SSLDIR/openssl.cnf
	echo "crl              = \$dir/crl.pem " >> $SSLDIR/openssl.cnf
	echo "RANDFILE         = \$dir/private/.rand " >> $SSLDIR/openssl.cnf
	echo "default_days     = 365 " >> $SSLDIR/openssl.cnf
	echo "default_crl_days = 30 " >> $SSLDIR/openssl.cnf
	echo "default_md       = sha1 " >> $SSLDIR/openssl.cnf
	echo "preserve         = no " >> $SSLDIR/openssl.cnf
	echo "policy           = policy_anything " >> $SSLDIR/openssl.cnf
	echo "name_opt         = ca_default " >> $SSLDIR/openssl.cnf
	echo "cert_opt         = ca_default " >> $SSLDIR/openssl.cnf
	echo "[ policy_anything ] " >> $SSLDIR/openssl.cnf
	echo "countryName             = optional " >> $SSLDIR/openssl.cnf
	echo "stateOrProvinceName     = optional " >> $SSLDIR/openssl.cnf
	echo "localityName            = optional " >> $SSLDIR/openssl.cnf
	echo "organizationName        = optional " >> $SSLDIR/openssl.cnf
	echo "organizationalUnitName  = optional " >> $SSLDIR/openssl.cnf
	echo "commonName              = supplied " >> $SSLDIR/openssl.cnf
	echo "emailAddress            = optional " >> $SSLDIR/openssl.cnf
	echo "[ req ] " >> $SSLDIR/openssl.cnf
	echo "default_bits            = 1024 " >> $SSLDIR/openssl.cnf
	echo "default_md              = sha1 " >> $SSLDIR/openssl.cnf
	echo "default_keyfile         = privkey.pem " >> $SSLDIR/openssl.cnf
	echo "distinguished_name      = req_distinguished_name " >> $SSLDIR/openssl.cnf
	echo "x509_extensions         = v3_ca " >> $SSLDIR/openssl.cnf
	echo "string_mask             = nombstr " >> $SSLDIR/openssl.cnf
	echo "[ req_distinguished_name ] " >> $SSLDIR/openssl.cnf
	echo "countryName             = Country Name (2 letter code) " >> $SSLDIR/openssl.cnf
	echo "countryName_min         = 2 " >> $SSLDIR/openssl.cnf
	echo "countryName_max         = 2 " >> $SSLDIR/openssl.cnf
	echo "stateOrProvinceName     = State or Province Name (full name) " >> $SSLDIR/openssl.cnf
	echo "localityName            = Locality Name (eg, city) " >> $SSLDIR/openssl.cnf
	echo "0.organizationName      = Organization Name (eg, company) " >> $SSLDIR/openssl.cnf
	echo "organizationalUnitName  = Organizational Unit Name (eg, section) " >> $SSLDIR/openssl.cnf
	echo "commonName              = Common Name (eg, YOUR name) " >> $SSLDIR/openssl.cnf
	echo "commonName_max          = 64 " >> $SSLDIR/openssl.cnf
	echo "emailAddress            = Email Address " >> $SSLDIR/openssl.cnf
	echo "emailAddress_max        = 64 " >> $SSLDIR/openssl.cnf
	echo "[ usr_cert ] " >> $SSLDIR/openssl.cnf
	echo "basicConstraints        = CA:FALSE " >> $SSLDIR/openssl.cnf
	echo "nsCaRevocationUrl       = https://elbert.isi.jhu.edu/crl.pem " >> $SSLDIR/openssl.cnf
	echo "[ ssl_server ] " >> $SSLDIR/openssl.cnf
	echo "basicConstraints        = CA:FALSE " >> $SSLDIR/openssl.cnf
	echo "nsCertType              = server " >> $SSLDIR/openssl.cnf
	echo "keyUsage                = digitalSignature, keyEncipherment " >> $SSLDIR/openssl.cnf
	echo "extendedKeyUsage        = serverAuth, nsSGC, msSGC " >> $SSLDIR/openssl.cnf
	echo "nsComment               = 'OpenSSL Certificate for SSL Web Server' " >> $SSLDIR/openssl.cnf
	echo "[ ssl_client ] " >> $SSLDIR/openssl.cnf
	echo "basicConstraints        = CA:FALSE " >> $SSLDIR/openssl.cnf
	echo "nsCertType              = client " >> $SSLDIR/openssl.cnf 
	echo "keyUsage                = digitalSignature, keyEncipherment " >> $SSLDIR/openssl.cnf 
	echo "extendedKeyUsage        = clientAuth " >> $SSLDIR/openssl.cnf
	echo "nsComment               = 'OpenSSL Certificate for SSL Client'" >> $SSLDIR/openssl.cnf 
	echo "[ v3_req ] " >> $SSLDIR/openssl.cnf
	echo "basicConstraints = CA:FALSE " >> $SSLDIR/openssl.cnf
	echo "keyUsage         = nonRepudiation, digitalSignature, keyEncipherment " >> $SSLDIR/openssl.cnf 
	echo "[ v3_ca ] " >> $SSLDIR/openssl.cnf
	echo "basicConstraints        = critical, CA:true, pathlen:0 " >> $SSLDIR/openssl.cnf
	echo "nsCertType              = sslCA " >> $SSLDIR/openssl.cnf
	echo "keyUsage                = cRLSign, keyCertSign " >> $SSLDIR/openssl.cnf
	echo "extendedKeyUsage        = serverAuth, clientAuth " >> $SSLDIR/openssl.cnf
	echo "nsComment               = 'OpenSSL CA Certificate' " >> $SSLDIR/openssl.cnf 
	echo "[ crl_ext ] " >> $SSLDIR/openssl.cnf
	echo "basicConstraints        = CA:FALSE " >> $SSLDIR/openssl.cnf
	echo "keyUsage                = digitalSignature, keyEncipherment" >> $SSLDIR/openssl.cnf 
	echo "nsComment               = 'OpenSSL generated CRL' " >> $SSLDIR/openssl.cnf



elif [ "$1" == "-ssl2" ]; then
	if [ "$2" == "-v" ]; then
		echo "Next, we will create our self-signed CA's certificate and private/public key pair.  Additionally, you will be prompted to provide information for the certificate request.  When asked for Common Name input, provide your domain name with a CA appended to the end (i.e. elbert.isi.jhu.edu CA).  This will ensure that CA and server CN are different."
                echo "  req  - X.509 Certificate Signing Request (CSR) Management."
                echo "  x509 - X.509 Certificate Data Management."
                echo "  dates- general timestamp of validity."
                echo "  sha1 - message digest."
		echo "..."
		echo "Executing: openssl req -config $SSLDIR/openssl.cnf -new -x509 -days 361 -sha1 -newkey rsa:1024 -keyout $SSLDIR/private/ca.key -out $SSLDIR/ca.crt"
	fi
	openssl req -config $SSLDIR/openssl.cnf -new -x509 -days 361 -sha1 -newkey rsa:1024 -keyout $SSLDIR/private/ca.key -out $SSLDIR/ca.crt 
	echo "You will want to publish the ca.crt to the web for client download and install to browser."

elif [ "$1" == "-ssl3" ]; then
	if [ "$2" == "-v" ]; then
		echo "Server key public/private key pair creation, and creating the certificate request for CA signing. Remember that the CN has to be your fully qualified domain name (i.e. hostname --FQDN)."
		echo "..."
		echo "Executing: openssl req -new -sha1 -newkey rsa:1024 -nodes -keyout server.key -out request.pem"
		echo "Executing: mv $SSLDIR/request.pem $SSLDIR/requests/"
		echo "..."
		echo "Signing the certificate request (executed by CA host only)."
		echo "Executing: openssl ca -config $SSLDIR/openssl.cnf -policy policy_anything -extensions ssl_server -out $SSLDIR/requests/signed.pem -infiles $SSLDIR/requests/request.pem"
		echo "Executing: openssl x509 -in $SSLDIR/requests/signed.pem -out $SSLDIR/requests/server.crt"  
	fi
	openssl req -new -sha1 -newkey rsa:1024 -nodes -keyout server.key -out request.pem
	mv request.pem $SSLDIR/requests/
	mv server.key $SSLDIR/
	openssl ca -config $SSLDIR/openssl.cnf -policy policy_anything -extensions ssl_server -out $SSLDIR/requests/signed.pem -infiles $SSLDIR/requests/request.pem
	openssl x509 -in $SSLDIR/requests/signed.pem -out $SSLDIR/requests/server.crt
	echo "..."
	echo "To revoke cert via serial number (compromised cert), execute -opt1."
	echo "To set-up a revocation list, CRL, execute -opt2."



elif [ "$1" == "-opt1" ]; then
	if [ "$2" == "-v" ]; then
		echo "To revoke a certificate, we locate our serial number in our index.txt database file, and revoke that way.  As such, you should change this serial variable manually within this bash script."
		echo "Executing: openssl ca -config $SSLDIR/openssl.cnf -revoke $SSLDIR/newcerts/1.pem"
	fi
	openssl ca -config $SSLDIR/openssl.cnf -revoke $SSLDIR/newcerts/1.pem



elif [ "$1" == "-opt2" ]; then
	if [ "$2" == "-v" ]; then
		echo "To create a CRL (Certificate Revocation List), we use gencrl in openssl.  Also, we will create a DER-encoded CRL as to meet other browser specifications."
		echo "Executing: openssl ca -config openssl ca -config $SSLDIR/openssl.cnf -revoke $SSLDIR/newcerts/1.pem"
		echo "Executing: openssl crl -in $SSLDIR/crl.pem -out $SSLDIR/revoke_certs.crl -outform DER"
	fi
	openssl ca -config openssl ca -config $SSLDIR/openssl.cnf -revoke $SSLDIR/newcerts/1.pem
	openssl crl -in $SSLDIR/crl.pem -out $SSLDIR/revoke_certs.crl -outform DER




elif [ "$1" == "-ssl4" ]; then
	if [ "$2" == "-v" ]; then
		echo "Using Apache2 with client certificates.  First step, enable client authentication via modification of the ssl default vhost line SSLVerifyClient require, and SSLVerifyDepth 1."
		echo "Than move the ca.crt with your other certs, and modify line SSLCACertificateFile to point to that cert."
		echo "Executing: /etc/init.d/apache2 restart"
	fi
	#/etc/init.d/apache2 restart
	# Current the script doesn't do this.
	echo "Now only browsers with valid certs can visit the secured hospital page."
	echo "For test purposes of creating a client certificate, execute -opt3."



# Now only browsers with valid certs can visit the hosptial page.
elif [ "$1" == "-opt3" ]; then
	if [ "$2" == "-v" ]; then
		echo "Using different x.509 extensions we emulate the process of creating the web server certificate earlier, this time for the client.  This process could be automated via java web applet, and save the administrator time."
		echo "First we are gong to create a private/public key pair for the user & a certificate request.  This would be executed on the client-host."
		echo "Next, the CA verifies the information, copies it to the requests diretory, and signs the certificate."
		echo "Finally, the CA should send the certificate to the client-host.  The client-host finishes up his/her part via storing their private key with their certificate in the PKCS#12 format; finally, installing the *.p12 file into the browser."
                echo "  ca   - Certificate Authority (CA) Management."
		echo "..."
		echo "Executing (client): openssl req -new -sha1 -newkey rsa:1024 -nodes -keyout client.key -out request.pem -subj '/O=Test/OU=Test/CN=Individual User' "
		echo "Executing (CA): openssl ca -config $SSLDIR/openssl.cnf -policy policy_anything -extensions ssl_client -out $SSLDIR/requests/signed.pem -infiles $SSLDIR/requests/request.pem "
		echo "Executing (client): openssl pkcs12 -export -clcerts -in signed.pem -inkey client.key -out client.p12"
		
	fi
	mkdir -p client/keys client/requests
	openssl req -new -sha1 -newkey rsa:1024 -nodes -keyout client/keys/client.key -out client/requests/request.pem -subj '/O=Test/OU=Test/CN=Individual User'
	openssl ca -config $SSLDIR/openssl.cnf -policy policy_anything -extensions ssl_client -out client/signed.pem -infiles client/requests/request.pem
	openssl pkcs12 -export -clcerts -in client/signed.pem -inkey client/keys/client.key -out client.p12

elif [ "$1" == "-ssl5" ]; then
	if [ "$2" == "-v" ]; then
		echo "server.crt: The self-signed server certificate."
		echo "server.key: The private server key, does not require a password when starting Apache."
		echo "ca.crt: The Certificate Authority's own certificate."
		echo "ca.key: The key which the CA uses to sign server signing requests."
	fi
	openssl rsa -noout -text -in $SSLDIR/server.key
	echo "..."
	openssl req -noout -text -in $SSLDIR/requests/server.crt
	echo "..."
	openssl rsa -noout -text -in $SSLDIR/private/ca.key
	echo "..."
	openssl x509 -noout -text -in $SSLDIR/ca.crt


elif [ "$1" == "--abecert" ]; then
        if [ $# -lt 2 ]; then
		echo "Come on, you need at least one attribute!"
		echo "i.e. ./testSSL --abecert attrONE attrTWO attrTHREE"
		exit -1
	fi
	
	shift
	export strAttributes="/C=US/ST=Baltimore/L=JHU/CN=$*"

	echo "Files will be placed here... $ABEDIR."
	mkdir -p $ABEDIR $ABEDIR/certs $ABEDIR/crl $ABEDIR/newcerts $ABEDIR/private $ABEDIR/requests
	touch $ABEDIR/index.txt
	echo "01" > $ABEDIR/serial
	chmod 700 $ABEDIR

	# I'm sure there is an easier way to do this, but this will save us from problems with using the default openssl.cnf.
	chmod 700 $ABEDIR
	echo "# =================================================" > $ABEDIR/openssl.cnf 
	echo "# OpenSSL configuration file " >> $ABEDIR/openssl.cnf
	echo "# ================================================= " >> $ABEDIR/openssl.cnf
	echo "RANDFILE         = $ABEDIR/.rnd " >> $ABEDIR/openssl.cnf
	echo "[ ca ] " >> $ABEDIR/openssl.cnf
	echo "default_ca       = CA_default " >> $ABEDIR/openssl.cnf
	echo "[ CA_default ] " >> $ABEDIR/openssl.cnf
	echo "dir              = $ABEDIR " >> $ABEDIR/openssl.cnf
	echo "certs            = \$dir/certs " >> $ABEDIR/openssl.cnf
	echo "new_certs_dir    = \$dir/newcerts " >> $ABEDIR/openssl.cnf
	echo "crl_dir          = \$dir/crl " >> $ABEDIR/openssl.cnf
	echo "database         = \$dir/index.txt " >> $ABEDIR/openssl.cnf
	echo "private_key      = \$dir/private/ca.key " >> $ABEDIR/openssl.cnf
	echo "certificate      = \$dir/ca.crt " >> $ABEDIR/openssl.cnf
	echo "serial           = \$dir/serial " >> $ABEDIR/openssl.cnf
	echo "crl              = \$dir/crl.pem " >> $ABEDIR/openssl.cnf
	echo "RANDFILE         = \$dir/private/.rand " >> $ABEDIR/openssl.cnf
	echo "default_days     = 365 " >> $ABEDIR/openssl.cnf
	echo "default_crl_days = 30 " >> $ABEDIR/openssl.cnf
	echo "default_md       = sha1 " >> $ABEDIR/openssl.cnf
	echo "preserve         = no " >> $ABEDIR/openssl.cnf
	echo "policy           = policy_anything " >> $ABEDIR/openssl.cnf
	echo "name_opt         = ca_default " >> $ABEDIR/openssl.cnf
	echo "cert_opt         = ca_default " >> $ABEDIR/openssl.cnf
	echo "[ policy_anything ] " >> $ABEDIR/openssl.cnf
	echo "countryName             = optional " >> $ABEDIR/openssl.cnf
	echo "stateOrProvinceName     = optional " >> $ABEDIR/openssl.cnf
	echo "localityName            = optional " >> $ABEDIR/openssl.cnf
	echo "organizationName        = optional " >> $ABEDIR/openssl.cnf
	echo "organizationalUnitName  = optional " >> $ABEDIR/openssl.cnf
	echo "commonName              = supplied " >> $ABEDIR/openssl.cnf
	echo "emailAddress            = optional " >> $ABEDIR/openssl.cnf
	echo "[ req ] " >> $ABEDIR/openssl.cnf
	echo "default_bits            = 1024 " >> $ABEDIR/openssl.cnf
	echo "default_md              = sha1 " >> $ABEDIR/openssl.cnf
	echo "default_keyfile         = privkey.pem " >> $ABEDIR/openssl.cnf
	echo "distinguished_name      = req_distinguished_name " >> $ABEDIR/openssl.cnf
	echo "x509_extensions         = v3_ca " >> $ABEDIR/openssl.cnf
	echo "string_mask             = nombstr " >> $ABEDIR/openssl.cnf
	echo "[ req_distinguished_name ] " >> $ABEDIR/openssl.cnf
	echo "countryName             = Country Name (2 letter code) " >> $ABEDIR/openssl.cnf
	echo "countryName_min         = 2 " >> $ABEDIR/openssl.cnf
	echo "countryName_max         = 2 " >> $ABEDIR/openssl.cnf
	echo "stateOrProvinceName     = State or Province Name (full name) " >> $ABEDIR/openssl.cnf
	echo "localityName            = Locality Name (eg, city) " >> $ABEDIR/openssl.cnf
	echo "0.organizationName      = Organization Name (eg, company) " >> $ABEDIR/openssl.cnf
	echo "organizationalUnitName  = Organizational Unit Name (eg, section) " >> $ABEDIR/openssl.cnf
	echo "commonName              = Common Name (eg, YOUR name) " >> $ABEDIR/openssl.cnf
	echo "commonName_max          = 64 " >> $ABEDIR/openssl.cnf
	echo "emailAddress            = Email Address " >> $ABEDIR/openssl.cnf
	echo "emailAddress_max        = 64 " >> $ABEDIR/openssl.cnf
	echo "[ usr_cert ] " >> $ABEDIR/openssl.cnf
	echo "basicConstraints        = CA:FALSE " >> $ABEDIR/openssl.cnf
	echo "nsCaRevocationUrl       = https://elbert.isi.jhu.edu/crl.pem " >> $ABEDIR/openssl.cnf
	echo "[ ssl_server ] " >> $ABEDIR/openssl.cnf
	echo "basicConstraints        = CA:FALSE " >> $ABEDIR/openssl.cnf
	echo "nsCertType              = server " >> $ABEDIR/openssl.cnf
	echo "keyUsage                = digitalSignature, keyEncipherment " >> $ABEDIR/openssl.cnf
	echo "extendedKeyUsage        = serverAuth, nsSGC, msSGC " >> $ABEDIR/openssl.cnf
	echo "nsComment               = 'OpenSSL Certificate for SSL Web Server' " >> $ABEDIR/openssl.cnf
	echo "[ ssl_client ] " >> $ABEDIR/openssl.cnf
	echo "basicConstraints        = CA:FALSE " >> $ABEDIR/openssl.cnf
	echo "nsCertType              = client " >> $ABEDIR/openssl.cnf 
	echo "keyUsage                = digitalSignature, keyEncipherment " >> $ABEDIR/openssl.cnf 
	echo "extendedKeyUsage        = clientAuth " >> $ABEDIR/openssl.cnf
	echo "nsComment               = 'OpenSSL Certificate for SSL Client'" >> $ABEDIR/openssl.cnf 
	echo "[ v3_req ] " >> $ABEDIR/openssl.cnf
	echo "basicConstraints = CA:FALSE " >> $ABEDIR/openssl.cnf
	echo "keyUsage         = nonRepudiation, digitalSignature, keyEncipherment " >> $ABEDIR/openssl.cnf 
	echo "[ v3_ca ] " >> $ABEDIR/openssl.cnf
	echo "basicConstraints        = critical, CA:true, pathlen:0 " >> $ABEDIR/openssl.cnf
	echo "nsCertType              = sslCA " >> $ABEDIR/openssl.cnf
	echo "keyUsage                = cRLSign, keyCertSign " >> $ABEDIR/openssl.cnf
	echo "extendedKeyUsage        = serverAuth, clientAuth " >> $ABEDIR/openssl.cnf
	echo "nsComment               = 'OpenSSL CA Certificate' " >> $ABEDIR/openssl.cnf 
	echo "[ crl_ext ] " >> $ABEDIR/openssl.cnf
	echo "basicConstraints        = CA:FALSE " >> $ABEDIR/openssl.cnf
	echo "keyUsage                = digitalSignature, keyEncipherment" >> $ABEDIR/openssl.cnf 
	echo "nsComment               = 'OpenSSL generated CRL' " >> $ABEDIR/openssl.cnf

	echo "Generate DSA Parameters..."
	openssl dsaparam 2048 -out $ABEDIR/private/dsaparams.pem
	echo "Generate a DSA key..."
	openssl gendsa -out $ABEDIR/private/dsarootkey.pem $ABEDIR/private/dsaparams.pem
	echo "Generating self-signed root certificate..."
	openssl req -config $ABEDIR/openssl.cnf -newkey dsa:$ABEDIR/private/dsaparams.pem -keyout $ABEDIR/private/dsarootkey.pem -new -x509 -days 365 -out $ABEDIR/certs/rootcert_CA.pem -subj '/C=US/ST=Baltimore/L=JHU/CN=ABE Attributes CA'
	echo "Printing self-signed root certificate..."
	openssl x509 -text -in $ABEDIR/certs/rootcert_CA.pem
	echo "----- asn1parse -----"
	openssl asn1parse -in $ABEDIR/certs/rootcert_CA.pem 
	echo "Generate certificate request..."
	openssl req -config $ABEDIR/openssl.cnf -newkey dsa:$ABEDIR/private/dsaparams.pem -keyout $ABEDIR/requests/abe_dsakey.pem -new -days 365 -out $ABEDIR/requests/abe_dsareq.pem -subj "${strAttributes}"
	echo "Printing certificate request..."
	openssl req -text -in $ABEDIR/requests/abe_dsareq.pem
	echo "Issue a certificate per request..."
	openssl x509 -days 180 -CA $ABEDIR/certs/rootcert_CA.pem -CAkey $ABEDIR/private/dsarootkey.pem -req -CAcreateserial -CAserial $ABEDIR/ca.sri -in $ABEDIR/requests/abe_dsareq.pem -out $ABEDIR/newcerts/abe_attr.pem
	echo "View issued certificate..."
	openssl x509 -text -in $ABEDIR/newcerts/abe_attr.pem
	echo "----- asn1parse -----"
	openssl asn1parse -in $ABEDIR/newcerts/abe_attr.pem
	echo "..."
	echo "The certificate you want for the iPhone application is in $ABEDIR/newcerts/abe_attr.pem" 
	echo "The key / request pair can both be found under $ABEDIR/requests/"

       # CRL not yet implemented.
fi



