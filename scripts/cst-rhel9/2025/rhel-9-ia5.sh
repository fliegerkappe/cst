#! /bin/bash

# IA-5 Manage system authenticators by:
# a. Verifying, as part of the initial authenticator distribution, the identity of the individual, group, role, service, or device receiving the authenticator;
# b. Establishing initial authenticator content for any authenticators issued by the organization;
# c. Ensuring that authenticators have sufficient strength of mechanism for their intended use;
# d. Establishing and implementing administrative procedures for initial authenticator distribution, for lost or compromised or damaged authenticators, and for revoking authenticators;
# e. Changing default authenticators prior to first use;
# f. Changing or refreshing authenticators [Assignment: organization-defined time period by authenticator type] or when [Assignment: organization-defined events] occur;
# g. Protecting authenticator content from unauthorized disclosure and modification;
# h. Requiring individuals to take, and having devices implement, specific controls to protect authenticators; and
# i. Changing authenticators for group or role accounts when membership to those accounts changes

# CONTROL: The information system uniquely identifies and authenticates [Assignment: organization-defined specific and/or types of devices] before establishing a [Selection (one or more): local; remote; network] connection."

# Check if the script is being run as root
if [ "$EUID" -ne 0 ]
then
   echo "Please run with sudo or as root"
   exit
fi

# Color declarations
RED=`echo    "\e[31;1m"`        # bold red
GRN=`echo    "\e[32;1m"`        # bold green
BLD=`echo    "\e[0;1m"`         # bold black
CYN=`echo    "\e[33;1;35m"`     # bold cyan
YLO=`echo    "\e[93;1m"`        # bold yellow
BAR=`echo    "\e[11;1;44m"`     # blue separator bar
NORMAL=`echo "\e[0m"`           # normal

stig="Red Hat Enterprise Linux 9 Version: 2 Release: 5 Benchmark Date: 02 Jul 2025"

hostname="$(uname -n)"

if [[ -f /etc/redhat-release ]]
then
   os="$(cat /etc/redhat-release)"
else
   os="OS not defined"
fi

prog="$(basename $0)"

controlid="IA-5 Authenticator Management"

title1a="RHEL 9, for PKI-based authentication, must enforce authorized access to the corresponding private key."
title1b="Checking with: ssh-keygen -y -f /path/to/file"
title1c="Expecting: ${YLO}Nothing returned
	   NOTE: If \"/home/[username]/.ssh\" is not the right path, modify the search.
	   NOTE: If any private key is found that doesn't require a passphrase. This is a finding."${BLD}
cci1="CCI-000186"
stigid1="RHEL-09-611190"
severity1="CAT II"
ruleid1="SV-258127r958450"
vulned1="V-258127"

title2a="RHEL 9 must not have a File Transfer Protocol (FTP) server package installed."
title2b="Checking with: dnf list --installed vsftpd"
title2c="Expecting: ${YLO}Error: No matching Packages to list
           NOTE: If the \"ftp\" package is installed, this is a finding."${BLD}
cci2="CCI-000197 CCI-000381"
stigid2="RHEL-09-215015"
severity2="CAT I"
ruleid2="SV-257826r1106299"
vulnid2="V-257826"

title3a="RHEL 9 user account passwords for new users or password changes must have a 60-day maximum password lifetime restriction in /etc/login.defs."
title3b="Checking with: grep -i pass_max_days /etc/login.defs"
title3c="Expecting: ${YLO}PASS_MAX_DAYS 60
           NOTE: If the \"PASS_MAX_DAYS\" parameter value is greater than \"60\", or commented out, this is a finding."${BLD}
cci3="CCI-004066 CCI-000199"
stigid3="RHEL-09-411010"
severity3="CAT II"
ruleid3="SV-258041r1038967"
vulnid3="V-258041"

title4a="RHEL 9 user account passwords must have a 60-day maximum password lifetime restriction."
title4b="Checking with: 
           a. awk -F: '$5 > 60 {printf \"%s %d\\\\n\", \$1, \$5}' /etc/shadow
	   b. awk -F: '$5 <= 0 {printf \"%s %d\\\\n\", \$1, \$5}' /etc/shadow"
title4c="Expecting: ${YLO}
           a. No interactive user accounts with a password lifetime over 60 days.
	   b. No interactive user accounts with a password lifetime less than 1 day.
           NOTE: If any results are returned that are not associated with a system account, this is a finding."${BLD}
cci4="CCI-004066 CCI-000199"
stigid4="RHEL-09-411015"
severity4="CAT II"
ruleid4="SV-258042r1045133"
vulnid4="V-258042"

title5a="RHEL 9 must ensure the password complexity module in the system-auth file is configured for three retries or less."
title5b="Checking with: grep -w retry /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf"
title5c="Expecting: ${YLO}retry = 3
           NOTE: If the value of \"retry\" is set to \"0\" or greater than \"3\", or is missing, this is a finding."${BLD}
cci5="CCI-004066 CCI-000192"
stigid5="RHEL-09-611010"
severity5="CAT II"
ruleid5="SV-258091r1045185"
vulnid5="V-258091"

title6a="RHEL 9 must ensure the password complexity module is enabled in the password-auth file."
title6b="Checking with: grep pam_pwquality /etc/pam.d/password-auth"
title6c="Expecting: ${YLO}
           password required pam_pwquality.so
           NOTE: If the command does not return a line containing the value \"pam_pwquality.so\", or the line is commented out, this is a finding."${BLD}
cci6="CCI-004066 CCI-000192 CCI-000193"
stigid6="RHEL-09-611040"
severity6="CAT II"
ruleid6="SV-258097r1045193"
vulnid6="V-258097"

title7a="RHEL 9 password-auth must be configured to use a sufficient number of hashing rounds."
title7b="Checking with: grep rounds /etc/pam.d/password-auth"
title7c="Expecting: ${YLO}
           password sufficient pam_unix.so sha512 ${BLD}rounds=100000${YLO}
           NOTE: If a matching line is not returned or \"rounds\" is less than \"100000\", this a finding."${BLD}
cci7="CCI-004062 CCI-000803 CCI-000196"
stigid7="RHEL-09-611050"
severity7="CAT II"
ruleid7="SV-258099r1045198"
vulnid7="V-258099"

title8a="RHEL 9 system-auth must be configured to use a sufficient number of hashing rounds."
title8b="Checking with: grep rounds /etc/pam.d/system-auth"
title8c="Expecting: ${YLO}
           password sufficient pam_unix.so sha512 rounds=100000
           NOTE: If a matching line is not returned or \"rounds\" is less than \"100000\", this a finding."${BLD}
cci8="CCI-004062 CCI-000803 CCI-000196"
stigid8="RHEL-09-611055"
severity8="CAT II"
ruleid8="SV-258100r1045201"
vulnid8="V-258100"

title9a="RHEL 9 must enforce password complexity rules for the root account."
title9b="Checking with: grep enforce_for_root /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf"
title9c="Expecting: ${YLO}
           /etc/security/pwquality.conf:enforce_for_root
	   NOTE: If \"enforce_for_root\" is commented or missing, this is a finding."${BLD}
cci9="CCI-004066 CCI-000192 CCI-000193 CCI-000194 CCI-000195 CCI-000205 CCI-001619"
stigid9="RHEL-09-611060"
severity9="CAT II"
ruleid9="SV-258101r1045204"
vulnid9="V-258101"

title10a="RHEL 9 must enforce password complexity by requiring that at least one lowercase character be used."
title10b="Checking with: grep lcredit /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf"
title10c="Expecting: ${YLO}/etc/security/pwquality.conf:lcredit = -1
           NOTE: If the value of \"lcredit\" is a positive number or is commented out, this is a finding."${BLD}
cci10="CCI-004066 CCI-000193"
stigid10="RHEL-09-611065"
severity10="CAT II"
ruleid10="SV-258102r1045207"
vulnid10="V-258102"

title11a="RHEL 9 must enforce password complexity by requiring that at least one numeric character be used."
title11b="Checking with: grep dcredit /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf"
title11c="Expecting: ${YLO}/etc/security/pwquality.conf:dcredit = -1
           NOTE: If the value of \"dcredit\" is a positive number or is commented out, this is a finding."${BLD}
cci11="CCI-004066 CCI-000194"
stigid11="RHEL-09-611070"
severity11="CAT II"
ruleid11="SV-258103r1045210"
vulnid11="V-258103"

title12a="RHEL 9 passwords for new users or password changes must have a 24 hours minimum password lifetime restriction in /etc/login.defs."
title12b="Checking with: grep -i pass_min_days /etc/login.defs"
title12c="Expecting: ${YLO}PASS_MIN_DAYS 1
           NOTE: If the \"PASS_MIN_DAYS\" parameter value is not \"1\" or greater, or is commented out, this is a finding."${BLD}
cci12="CCI-004066 CCI-000198"
stigid12="RHEL-09-611075"
severity12="CAT II"
ruleid12="SV-258104r1015104"
vulnid12="V-258104"

title13a="RHEL 9 passwords must have a 24 hours minimum password lifetime restriction in /etc/shadow."
title13b="Checking with: awk -F: '\$4 < 1 {printf \"%s %d\\\\n\", \$1, \$4}' /etc/shadow"
title13c="Expecting: ${YLO}Nothing returned
           NOTE: If any results are returned that are not associated with a system account, this is a finding."${BLD}
cci13="CCI-004066 CCI-000198"
stigid13="RHEL-09-611080"
severity13="CAT II"
ruleid13="SV-258105r1045212"
vulnid13="V-258105"

title14a="RHEL 9 passwords must be created with a minimum of 15 characters."
title14b="Checking with: grep minlen /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf"
title14c="Expecting: ${YLO}minlen = 15
           NOTE: If the command does not return a \"minlen\" value of \"15\" or greater, does not return a line, or the line is commented out, this is a finding."${BLD}
cci14="CCI-004066 CCI-000205"
stigid14="RHEL-09-611090"
severity14="CAT II"
ruleid14="SV-258107r1045218"
vulnid14="V-258107"

title15a="RHEL 9 must enforce password complexity by requiring that at least one special character be used."
title15b="Checking with: grep ocredit /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf"
title15c="Expecting: ${YLO}ocredit = -1
           NOTE: If the value of \"ocredit\" is a positive number or is commented out, this is a finding."${BLD}
cci15="CCI-004066 CCI-001619"
stigid15="RHEL-09-611100"
severity15="CAT II"
ruleid15="SV-258109r1045220"
vulnid15="V-258109"

title16a="RHEL 9 must enforce password complexity by requiring that at least one uppercase character be used."
title16b="Checking with: grep ucredit /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf"
title16c="Expecting: ${YLO}ucredit = -1
           NOTE: If the value of \"ucredit\" is a positive number or is commented out, this is a finding."${BLD}
cci16="CCI-004066 CCI-000192"
stigid16="RHEL-09-611110"
severity16="CAT II"
ruleid16="SV-258111r1045226"
vulnid16="V-258111"

title17a="RHEL 9 must require the change of at least eight characters when passwords are changed."
title17b="Checking with: grep difok /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf"
title17c="Expecting: ${YLO}difok = 8
           NOTE: If the value of \"difok\" is set to less than "8", or is commented out, this is a finding."${BLD}
cci17="CCI-004066 CCI-000195"
stigid17="RHEL-09-611115"
severity17="CAT II"
ruleid17="SV-258112r1045229"
vulnid17="V-258112"

title18a="RHEL 9 must require the maximum number of repeating characters of the same character class be limited to four when passwords are changed."
title18b="Checking with: grep maxclassrepeat /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf"
title18c="Expecting: ${YLO}maxclassrepeat = 4
           NOTE: If the value of \"maxclassrepeat\" is set to \"0\", more than \"4\", or is commented out, this is a finding."${BLD}
cci18="CCI-004066 CCI-000195"
stigid18="RHEL-09-611120"
severity18="CAT II"
ruleid18="SV-258113r1045232"
vulnid18="V-258113"

title19a="RHEL 9 must require the maximum number of repeating characters be limited to three when passwords are changed."
title19b="Checking with: grep maxrepeat /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf"
title19c="Expecting: ${YLO}maxrepeat = 3
           NOTE: If the value of \"maxrepeat\" is set to more than "3", or is commented out, this is a finding."${BLD}
cci19="CCI-004066 CCI-000195"
stigid19="RHEL-09-611125"
severity19="CAT II"
ruleid19="SV-258114r1045235"
vulnid19="V-258114"

title20a="RHEL 9 must require the change of at least four character classes when passwords are changed."
title20b="Checking with: grep minclass /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf"
title20c="Expecting: ${YLO}minclass = 4
           NOTE: If the value of \"minclass\" is set to less than \"4\", or is commented out, this is a finding."${BLD}
cci20="CCI-004066 CCI-000195"
stigid20="RHEL-09-611130"
severity20="CAT II"
ruleid20="SV-258115r1045238"
vulnid20="V-258115"

title21a="RHEL 9 must be configured so that user and group account administration utilities are configured to store only encrypted representations of passwords."
title21b="Checking with: grep crypt_style /etc/libuser.con"
title21c="Expecting: ${YLO}crypt_style = sha512
           NOTE: If the \"crypt_style\" variable is not set to \"sha512\", is not in the defaults section, is commented out, or does not exist, this is a finding."${BLD}
cci21="CCI-004062 CCI-000196"
stigid21="RHEL-09-611135"
severity21="CAT II"
ruleid21="SV-258116r1045240"
vulnid21="V-258116"

title22a="RHEL 9 must be configured to use the shadow file to store only encrypted representations of passwords."
title22b="Checking with: grep -i encrypt_method /etc/login.defs"
title22c="Expecting: ${YLO}ENCRYPT_METHOD SHA512
           NOTE: If \"ENCRYPT_METHOD\" does not have a value of \"SHA512\", or the line is commented out, this is a finding."${BLD}
cci22="CCI-004062 CCI-000196"
stigid22="RHEL-09-611140"
severity22="CAT II"
ruleid22="SV-258117r1015116"
vulnid22="V-258117"

title23a="RHEL 9, for PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor."
title23b="Checking with: openssl x509 -text -in /etc/sssd/pki/sssd_auth_ca_db.pem"
title23c="Expecting: ${YLO}
           Certificate:
               Data:
                   Version: 3 (0x2)
                   Serial Number: 1 (0x1)
                   Signature Algorithm: sha256WithRSAEncryption
                   Issuer: C = US, O = U.S. Government, OU = DoD, OU = PKI, CN = DoD Root CA 3
                   Validity
                   Not Before: Mar 20 18:46:41 2012 GMT
                   Not After: Dec 30 18:46:41 2029 GMT
                   Subject: C = US, O = U.S. Government, OU = DoD, OU = PKI, CN = DoD Root CA 3
                   Subject Public Key Info:
                       Public Key Algorithm: rsaEncryption
           NOTE: If the root CA file is not a DOD-issued certificate with a valid date and installed in the /etc/sssd/pki/sssd_auth_ca_db.pem location, this is a finding."${BLD}
cci23="CCI-000185 CCI-004068 CCI-001991"
stigid23="RHEL-09-631010"
severity23="CAT II"
ruleid23="SV-258131r1015125"
vulnid23="V-258131"

title24a="RHEL 9 must map the authenticated identity to the user or group account for PKI-based authentication."
title24b="Checking with: find /etc/sssd/sssd.conf /etc/sssd/conf.d/ -type f -exec cat {} \;"
title24c="Expecting: ${YLO}
           [certmap/testing.test/rule_name]
           matchrule =<SAN>.*EDIPI@mil
           maprule = (userCertificate;binary={cert!bin})
           domains = testing.test
           NOTE: If the certmap section does not exist, ask the system administrator (SA) to indicate how certificates are mapped to accounts.
           NOTE: If there is no evidence of certificate mapping, this is a finding."${BLD}
cci24="CCI-000187"
stigid24="RHEL-09-631015"
severity24="CAT II"
ruleid24="SV-258132r1045260"
vulnid24="V-258132"

title25a="RHEL 9 must prohibit the use of cached authenticators after one day."
title25b="Checking with: 
           a. grep -ir cache_credentials /etc/sssd/sssd.conf /etc/sssd/conf.d/
	   b. grep -ir offline_credentials_expiration /etc/sssd/sssd.conf /etc/sssd/conf.d/"
title25c="Expecting: ${YLO}
           a. cache_credentials = true
	   b. offline_credentials_expiration = 1
           NOTE: If \"cache_credentials\" is set to \"false\" or missing from the configuration file, this is not a finding and no further checks are required.
	   NOTE: If \"offline_credentials_expiration\" is not set to a value of \"1\", this is a finding."${BLD}
cci25="CCI-002007"
stigid25="RHEL-09-631020"
severity25="CAT II"
ruleid25="SV-258133r1045263"
vulnid25="V-258133"

title26a="RHEL 9 must employ FIPS 140-3 approved cryptographic hashing algorithms for all stored passwords."
title26b="Checking with: cut -d: -f2 /etc/shadow"
title26c="Expecting: ${YLO}\"\$6$......\" for all interactive user accounts.
	   NOTE: If any interactive user password hash does not begin with \"\$6$\", this is a finding."${BLD}
cci26="CCI-000803 CCI-000196"
stigid26="RHEL-09-671015"
severity26="CAT II"
ruleid26="SV-258231r1069375"
vulnid26="V-258231"

title27a="RHEL 9 pam_unix.so module must be configured in the password-auth file to use a FIPS 140-3 approved cryptographic hashing algorithm for system authentication."
title27b="Checking with: grep \"^password.*pam_unix.so.*sha512\" /etc/pam.d/password-auth"
title27c="Expecting: ${YLO}password sufficient pam_unix.so sha512
           NOTE: If \"sha512\" is missing, or the line is commented out, this is a finding."${BLD}
cci27="CCI-004062 CCI-000196"
stigid27="RHEL-09-671025"
severity27="CAT II"
ruleid27="SV-258233r1015136"
vulnid27="V-258233"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid1${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid1${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid1${NORMAL}"
echo -e "${NORMAL}CCI:       $cci1${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 1:    ${BLD}$title1a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title1b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title1c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity1${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

interactive="$(awk -F: '($3>=0) {print $1}' /etc/passwd | grep -Ev 'nologin|sync|shutdown|halt|false')"

if [[ $interactive ]]
then
  count=0
  for user in ${interactive[@]}
  do
    # If /home/[username]/.ssh is not the right path to search, modify the next line. 
    prikeys="$(find 2>/dev/null /home/$user/.ssh -type f | grep -Ev ".pub|know|authorized")"
    if [[ $prikeys ]]
    then
      for key in ${prikeys[@]}
      do
	answer="$(yes | ssh-keygen -y -f 2>&1 $key)"
	if ! [[ $answer =~ "incorrect passphrase" ]]
	then
	  (( count++ ))
	  fail=1
	  echo -e "${NORMAL}RESULT:    ${RED}$key is not passphrase protected.${NORMAL}"
	fi
      done
    fi
  done
  if [[ $count == 0 ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
    fail=2
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}No interactive user accounts found${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, RHEL 9 enforces authorized access to the corresponding private key for PKI-based authentication.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}N/A, No private PKI-based autentication keys found. This requirement is Not Applicable.${NORMAL}" 
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, RHEL 9 does not enforce authorized access to the corresponding private key for PKI-based authentication.${NORMAL}"
fi



echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid2${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid2${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid2${NORMAL}"
echo -e "${NORMAL}CCI:       $cci2${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 2:    ${BLD}$title2a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title2b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title2c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity2${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${CYN}VERIFY, (See CM-7 Least Functionality: V-257826)"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid3${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid3${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid3${NORMAL}"
echo -e "${NORMAL}CCI:       $cci3${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 3:    ${BLD}$title3a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title3b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title3c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity3${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

maxdays="$(grep -i pass_max_days /etc/login.defs)"

if [[ $maxdays ]]
then
  for line in ${maxdays[@]}
  do
    value="$(echo $line | awk '{print $2}')"
    if (( $value <= 60 && $value > 0 )) && [[ ${line:0:1} != "#" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, RHEL 9 user account passwords for new users or password changes have a 60-day maximum password lifetime restriction in /etc/login.defs.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, RHEL 9 user account passwords for new users or password changes do not have a 60-day maximum password lifetime restriction in /etc/login.defs.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid4${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid4${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid4${NORMAL}"
echo -e "${NORMAL}CCI:       $cci4${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 4:    ${BLD}$title4a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title4b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title4c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity4${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

interactive="$(awk -F: '($3>=0) {print $1, $7}' /etc/passwd | grep -Ev 'nologin|sync|shutdown|halt|false')"
over="$(awk -F: '$5 > 60 {printf "%s %d\n", $1, $5}' /etc/shadow)"
under="$(awk -F: '$5 <= 0 {printf "%s %d\n", $1, $5}' /etc/shadow)"

found=0
for line in ${over[@]}
do
  username="$(echo $line | awk '{print $1}')"
  for acct in ${interactive[@]}
  do
    usr="$(echo $acct | awk '{print $1}')"
    if [[ $username == $usr ]]
    then
      fail=1
      echo -e "${NORMAL}RESULT:    ${RED}a. $line${NORMAL}"
      (( found++ ))
    fi
  done
done
if [[ $found == 0 ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}a. No interactive user accounts with a password lifetime over 60 days.${NORMAL}"
fi

found=0
for line in ${under[@]}
do
  username="$(echo $line | awk '{print $1}')"
  for acct in ${interactive[@]}
  do
    usr="$(echo $acct | awk '{print $1}')"
    if [[ $username == $usr ]]
    then
      fail=1
      echo -e "${NORMAL}RESULT:    ${RED}a. $line${NORMAL}"
      (( found++ ))
    fi
  done
done
if [[ $found == 0 ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}b. No interactive user accounts with a password lifetime less than 1 day.${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, RHEL 9 user account passwords have a 60-day maximum password lifetime restriction.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, RHEL 9 user account passwords do not have a 60-day maximum password lifetime restriction.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid5${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid5${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid5${NORMAL}"
echo -e "${NORMAL}CCI:       $cci5${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 5:    ${BLD}$title5a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title5b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title5c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity5${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

retry="$(grep -w retry 2>/dev/null /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf | grep -v "Per ")"

if [[ $retry ]]
then
  for line in  ${retry[@]}
  do
    file="$(echo $line | awk -F: '{print $1}')"
    setting="$(echo $line | awk -F: '{print $2}')"
    value="$(echo $setting | awk -F= '{print $2}' | sed 's/ //')"
    if (( $value > 0 && $value <= 3 )) && [[ ${setting:0:1} != "#" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$setting${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, RHEL 9 ensures the password complexity module in the system-auth file is configured for three retries or less.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, RHEL 9 does not ensure the password complexity module in the system-auth file is configured for three retries or less.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid6${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid6${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid6${NORMAL}"
echo -e "${NORMAL}CCI:       $cci6${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 6:    ${BLD}$title6a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title6b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title6c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity6${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

pwqual="$(grep pam_pwquality 2>/dev/null /etc/pam.d/password-auth | grep -v "Per ")"

if [[ $pwqual ]]
then
  for line in  ${pwqual[@]}
  do
    if [[ $pwqual =~ "password" && ($pwqual =~ "required" || $pwqual =~ "requisite") && ${pwqual:0:1} != "#" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$pwqual${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$pwqual${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}PASSED, RHEL 9 ensures the password complexity module is enabled in the password-auth file.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED, RHEL 9 does not ensure the password complexity module is enabled in the password-auth file.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid7${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid7${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid7${NORMAL}"
echo -e "${NORMAL}CCI:       $cci7${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 7:    ${BLD}$title7a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title7b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title7c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity7${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

rounds="$(grep rounds /etc/pam.d/password-auth)"

if [[ $rounds ]]
then
  for line in ${rounds[@]}
  do
    IFS=' ' read -a fieldvals <<< "${line}"
    for setting in ${fieldvals[@]}
    do
      if [[ $setting =~ "rounds=" ]]
      then
        val="$(echo $setting | awk -F= '{print $2}')"
	if (( $val >= 100000 ))
	then
	  fail=0
          echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
	else
          echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
	fi
      fi
    done
  done  
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${GRN}PASSED, RHEL 9 password-auth is configured to use a sufficient number of hashing rounds.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${RED}FAILED, RHEL 9 password-auth is not configured to use a sufficient number of hashing rounds.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid8${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid8${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid8${NORMAL}"
echo -e "${NORMAL}CCI:       $cci8${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 8:    ${BLD}$title8a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title8b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title8c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity8${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

rounds="$(grep rounds /etc/pam.d/system-auth)"

if [[ $rounds ]]
then
  for line in ${rounds[@]}
  do
    IFS=' ' read -a fieldvals <<< "${line}"
    for setting in ${fieldvals[@]}
    do
      if [[ $setting =~ "rounds=" ]]
      then
        val="$(echo $setting | awk -F= '{print $2}')"
        if (( $val >= 100000 ))
        then
          fail=0
          echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
        else
          echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
        fi
      fi
    done
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${GRN}PASSED, RHEL 9 system-auth is configured to use a sufficient number of hashing rounds.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${RED}FAILED, RHEL 9 system-auth is not configured to use a sufficient number of hashing rounds.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid9${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid9${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid9${NORMAL}"
echo -e "${NORMAL}CCI:       $cci9${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 9:    ${BLD}$title9a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title9b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title9c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity9${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

enforce="$(grep enforce_for_root /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf)"

if [[ $enforce ]]
then
  for line in ${enforce[@]}
  do
    file="$(echo $line | awk -F: '{print $1}')"
    setting="$(echo $line | awk -F: '{print $2}')"
    if [[ ${setting:0:1} != "#" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$setting${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${GRN}PASSED, RHEL 9 enforces password complexity rules for the root account.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${RED}FAILED, RHEL 9 enforces password complexity rules for the root account.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid10${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid10${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid10${NORMAL}"
echo -e "${NORMAL}CCI:       $cci10${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 10:   ${BLD}$title10a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title10b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title10c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity10${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

lcredit="$(grep lcredit 2>/dev/null /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf | grep -v "Per ")"

if [[ $lcredit ]]
then
  for line in ${lcredit[@]}
  do
    file="$(echo $line | awk -F: '{print $1}')"
    setting="$(echo $line | awk -F: '{print $2}')"
    value="$(echo $setting | awk -F= '{print $2}' | sed 's/ //')"
    if [[ $value == -1 && ${setting:0:1} != "#" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$setting${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${GRN}PASSED, RHEL 9 enforces password complexity by requiring that at least one lowercase character be used.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${RED}FAILED, RHEL 9 does not enforce password complexity by requiring that at least one lowercase character be used.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid11${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid11${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid11${NORMAL}"
echo -e "${NORMAL}CCI:       $cci11${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 11:   ${BLD}$title11a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title11b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title11c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity11${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

dcredit="$(grep dcredit 2>/dev/null /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf | grep -v "Per ")"

if [[ $dcredit ]]
then
  for line in ${dcredit[@]}
  do
    file="$(echo $line | awk -F: '{print $1}')"
    setting="$(echo $line | awk -F: '{print $2}')"
    value="$(echo $setting | awk -F= '{print $2}' | sed 's/ //')"
    if [[ $value == -1 && ${setting:0:1} != "#" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$setting${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${GRN}PASSED, RHEL 9 enforces password complexity by requiring that at least one numeric character be used.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${RED}FAILED, RHEL 9 does not enforce password complexity by requiring that at least one numeric character be used.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid12${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid12${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid12${NORMAL}"
echo -e "${NORMAL}CCI:       $cci12${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 12:   ${BLD}$title12a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title12b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title12c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity12${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

mindays="$(grep -i pass_min_days /etc/login.defs)"

if [[ $mindays ]]
then
  for line in ${mindays[@]}
  do
    value="$(echo $line | awk '{print $2}')"
    if (( $value >= 1 )) && [[ ${line:0:1} != "#" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${GRN}PASSED, RHEL 9 passwords for new users or password changes have a 24 hours minimum password lifetime restriction in /etc/login.defs.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${RED}FAILED, RHEL 9 passwords for new users or password changes do not have a 24 hours minimum password lifetime restriction in /etc/login.defs.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid13${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid13${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid13${NORMAL}"
echo -e "${NORMAL}CCI:       $cci13${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 13:   ${BLD}$title13a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title13b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title13c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity13${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

interactive="$(awk -F: '($3>=0) {print $1, $7}' /etc/passwd | grep -Ev 'nologin|sync|shutdown|halt|false')"
under="$(awk -F: '$4 < 1 {printf "%s %d\n", $1, $4}' /etc/shadow)"

found=0
for line in ${under[@]}
do
  username="$(echo $line | awk '{print $1}')"
  for acct in ${interactive[@]}
  do
    usr="$(echo $acct | awk '{print $1}')"
    if [[ $username == $usr ]]
    then
      fail=1
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      (( found++ ))
    fi
  done
done
if [[ $found == 0 ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}No interactive user accounts with a password lifetime less than 1 day.${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${GRN}PASSED, RHEL 9 passwords have a 24 hours minimum password lifetime restriction in /etc/shadow.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${RED}FAILED, RHEL 9 passwords do not have a 24 hours minimum password lifetime restriction in /etc/shadow.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid14${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid14${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid14${NORMAL}"
echo -e "${NORMAL}CCI:       $cci14${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 14:   ${BLD}$title14a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title14b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title14c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity14${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

minlen="$(grep minlen 2>/dev/null /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf | grep -v "Per ")"

if [[ $minlen ]]
then
  for line in ${minlen[@]}
  do
    file="$(echo $line | awk -F: '{print $1}')"
    setting="$(echo $line | awk -F: '{print $2}')"
    value="$(echo $setting | awk -F= '{print $2}' | sed 's/ //')"
    if (( $value >= 15 )) && [[ ${setting:0:1} != "#" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$setting${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity14, $controlid, $stigid14, $ruleid14, $cci14, $datetime, ${GRN}PASSED, RHEL 9 passwords are created with a minimum of 15 characters.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity14, $controlid, $stigid14, $ruleid14, $cci14, $datetime, ${RED}FAILED, RHEL 9 passwords are not created with a minimum of 15 characters.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid15${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid15${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid15${NORMAL}"
echo -e "${NORMAL}CCI:       $cci15${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 15:   ${BLD}$title15a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title15b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title15c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity15${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

ocredit="$(grep ocredit 2>/dev/null /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf | grep -v "Per ")"

if [[ $ocredit ]]
then
  for line in ${ocredit[@]}
  do
    file="$(echo $line | awk -F: '{print $1}')"
    setting="$(echo $line | awk -F: '{print $2}')"
    value="$(echo $setting | awk -F= '{print $2}' | sed 's/ //')"
    if [[ $value == -1 && ${setting:0:1} != "#" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$setting${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity15, $controlid, $stigid15, $ruleid15, $cci15, $datetime, ${GRN}PASSED, RHEL 9 enforces password complexity by requiring that at least one special character be used.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity15, $controlid, $stigid15, $ruleid15, $cci15, $datetime, ${RED}FAILED, RHEL 9 does not enforce password complexity by requiring that at least one special character be used.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid16${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid16${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid16${NORMAL}"
echo -e "${NORMAL}CCI:       $cci16${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 16:   ${BLD}$title16a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title16b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title16c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity16${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

ucredit="$(grep ucredit 2>/dev/null /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf | grep -v "Per ")"

if [[ $ucredit ]]
then
  for line in ${ucredit[@]}
  do
    file="$(echo $line | awk -F: '{print $1}')"
    setting="$(echo $line | awk -F: '{print $2}')"
    value="$(echo $setting | awk -F= '{print $2}' | sed 's/ //')"
    if [[ $value == -1 && ${setting:0:1} != "#" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$setting${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity16, $controlid, $stigid16, $ruleid16, $cci16, $datetime, ${GRN}PASSED, RHEL 9 enforces password complexity by requiring that at least one uppercase character be used.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity16, $controlid, $stigid16, $ruleid16, $cci16, $datetime, ${RED}FAILED, RHEL 9 does not enforce password complexity by requiring that at least one uppercase character be used.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid17${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid17${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid17${NORMAL}"
echo -e "${NORMAL}CCI:       $cci17${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 17:   ${BLD}$title17a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title17b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title17c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity17${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

difok="$(grep difok 2>/dev/null /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf | grep -v "Per ")"

if [[ $difok ]]
then
  for line in ${difok[@]}
  do
    file="$(echo $line | awk -F: '{print $1}')"
    setting="$(echo $line | awk -F: '{print $2}')"
    value="$(echo $setting | awk -F= '{print $2}' | sed 's/ //')"
    if (( $value >= 8 )) && [[ ${setting:0:1} != "#" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$setting${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity17, $controlid, $stigid17, $ruleid17, $cci17, $datetime, ${GRN}PASSED, RHEL 9 requires the change of at least eight characters when passwords are changed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity17, $controlid, $stigid17, $ruleid17, $cci17, $datetime, ${RED}FAILED, RHEL 9 does not require the change of at least eight characters when passwords are changed.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid18${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid18${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid18${NORMAL}"
echo -e "${NORMAL}CCI:       $cci18${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 18:   ${BLD}$title18a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title18b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title18c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity18${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

maxclass="$(grep maxclassrepeat 2>/dev/null /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf | grep -v "Per ")"

if [[ $maxclass ]]
then
  for line in ${maxclass[@]}
  do
    file="$(echo $line | awk -F: '{print $1}')"
    setting="$(echo $line | awk -F: '{print $2}')"
    value="$(echo $setting | awk -F= '{print $2}' | sed 's/ //')"
    if (( $value >= 4 )) && [[ ${setting:0:1} != "#" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$setting${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity18, $controlid, $stigid18, $ruleid18, $cci18, $datetime, ${GRN}PASSED, RHEL 9 requires the maximum number of repeating characters of the same character class be limited to four when passwords are changed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity18, $controlid, $stigid18, $ruleid18, $cci18, $datetime, ${RED}FAILED, RHEL 9 does not require the maximum number of repeating characters of the same character class be limited to four when passwords are changed.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid19${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid19${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid19${NORMAL}"
echo -e "${NORMAL}CCI:       $cci19${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 19:   ${BLD}$title19a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title19b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title19c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity19${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

maxrepeat="$(grep maxrepeat 2>/dev/null /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf | grep -v "Per ")"

if [[ $maxrepeat ]]
then
  for line in ${maxrepeat[@]}
  do
    file="$(echo $line | awk -F: '{print $1}')"
    setting="$(echo $line | awk -F: '{print $2}')"
    value="$(echo $setting | awk -F= '{print $2}' | sed 's/ //')"
    if (( $value <= 3 )) && [[ ${setting:0:1} != "#" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$setting${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity19, $controlid, $stigid19, $ruleid19, $cci19, $datetime, ${GRN}PASSED, RHEL 9 requires the maximum number of repeating characters be limited to three when passwords are changed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity19, $controlid, $stigid19, $ruleid19, $cci19, $datetime, ${RED}FAILED, RHEL 9 does not require the maximum number of repeating characters be limited to three when passwords are changed.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid20${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid20${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid20${NORMAL}"
echo -e "${NORMAL}CCI:       $cci20${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 20:   ${BLD}$title20a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title20b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title20c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity20${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

minclass="$(grep minclass 2>/dev/null /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf | grep -v "Per ")"

if [[ $minclass ]]
then
  for line in ${minclass[@]}
  do
    file="$(echo $line | awk -F: '{print $1}')"
    setting="$(echo $line | awk -F: '{print $2}')"
    value="$(echo $setting | awk -F= '{print $2}' | sed 's/ //')"
    if (( $value >= 4 )) && [[ ${setting:0:1} != "#" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$setting${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity20, $controlid, $stigid20, $ruleid20, $cci20, $datetime, ${GRN}PASSED, RHEL 9 requires the change of at least four character classes when passwords are changed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity20, $controlid, $stigid20, $ruleid20, $cci20, $datetime, ${RED}FAILED, RHEL 9 does not require the change of at least four character classes when passwords are changed.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid21${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid21${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid21${NORMAL}"
echo -e "${NORMAL}CCI:       $cci21${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 21:   ${BLD}$title21a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title21b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title21c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity21${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

style="$(grep crypt_style 2>/dev/null /etc/libuser.conf | grep -v "Per ")"

if [[ $style ]]
then
  value="$(echo $style | awk -F= '{print $2}' | sed 's/ //')"
  if [[ $value == "sha512" && ${style:0:1} != "#" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${BLD}$style${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}$style${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity21, $controlid, $stigid21, $ruleid21, $cci21, $datetime, ${GRN}PASSED, RHEL 9 is configured so that user and group account administration utilities are configured to store only encrypted representations of passwords.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity21, $controlid, $stigid21, $ruleid21, $cci21, $datetime, ${RED}FAILED, RHEL 9 is not configured so that user and group account administration utilities are configured to store only encrypted representations of passwords.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid22${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid22${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid22${NORMAL}"
echo -e "${NORMAL}CCI:       $cci22${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 22:   ${BLD}$title22a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title22b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title22c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity22${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

method="$(grep -i encrypt_method /etc/login.defs)"

if [[ $method ]]
then
  for line in ${method[@]}
  do
    encryption="$(echo $line | awk '{print tolower($2)}')"
    if [[ $encryption == "sha512" && ${method:0:1} != "#" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity22, $controlid, $stigid22, $ruleid22, $cci22, $datetime, ${GRN}PASSED, RHEL 9 is configured to use the shadow file to store only encrypted representations of passwords.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity22, $controlid, $stigid22, $ruleid22, $cci22, $datetime, ${RED}FAILED, RHEL 9 is not configured to use the shadow file to store only encrypted representations of passwords.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid23${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid23${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid23${NORMAL}"
echo -e "${NORMAL}CCI:       $cci23${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 23:   ${BLD}$title23a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title23b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title23c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity23${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

rootca="$(openssl x509 -text -in 2>/dev/null /etc/sssd/pki/sssd_auth_ca_db.pem)"
found=0
notbefore=0
notafter=0

if [[ $rootca ]]
then
  now="$(date +%s)"
  for line in ${rootca[@]}
  do
    if [[ $line =~ "DoD Root CA" ]]
    then
      found=1
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    elif [[ $line =~ "Not Before" ]]
    then
      nbd="$(echo $line | awk -F "Not Before" '{print $2}' | sed 's/: \+//' | sed 's/GMT//')"
      notbeforedate="$(date -d $nbd '+%s')"
      if [[ $now < $notbeforedate ]]
      then
	echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      else
	notbefore=1
        echo -e "${NORMAL}RESULT:    $line${NORMAL}"
      fi
    elif [[ $line =~ "Not After" ]]
    then
      nad="$(echo $line | awk -F "Not After" '{print $2}' | sed 's/: \+//' | sed 's/GMT//')"
      notafterdate="$(date -d $nad '+%s')"
      if [[ $now > $notafterdate ]]
      then
	echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      else
	notafter=1
        echo -e "${NORMAL}RESULT:    $line${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    $line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $found == 1 && $notbefore == 1 && $notafter == 1 ]]
then
  fail=0
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity23, $controlid, $stigid23, $ruleid23, $cci23, $datetime, ${GRN}PASSED, RHEL 9 validates certificates for PKI-based authentication by constructing a certification path (which includes status information) to an accepted trust anchor.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity23, $controlid, $stigid23, $ruleid23, $cci23, $datetime, ${RED}FAILED, RHEL 9 does not validate certificates for PKI-based authentication by constructing a certification path (which includes status information) to an accepted trust anchor.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid24${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid24${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid24${NORMAL}"
echo -e "${NORMAL}CCI:       $cci24${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 24:   ${BLD}$title24a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title24b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title24c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity24${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

certmap="$(find 2>/dev/null /etc/sssd/sssd.conf /etc/sssd/conf.d/ -type f -exec cat {} \;)"

if [[ $certmap ]]
then
  for line in ${certmap[@]}
  do
    if [[ $line =~ \[([^\]]+)\] ]]
    then
      found=0
      if [[ $line =~ "certmap" ]]
      then
	found=1
        echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
      else
	echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
      fi
    elif [[ $found == 1 && ($line =~ "matchrule" || $line =~ "maprule" || $line =~ "domains") ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity24, $controlid, $stigid24, $ruleid24, $cci24, $datetime, ${CYN}VERIFY, Ask the system administrator (SA) or information system security officer (ISSO) to verify that the certificate of the user or group is mapped to the corresponding user or group in the \"sssd.conf\" file.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity24, $controlid, $stigid24, $ruleid24, $cci24, $datetime, ${RED}FAILED, RHEL 9 does not map the authenticated identity to the user or group account for PKI-based authentication.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid25${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid25${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid25${NORMAL}"
echo -e "${NORMAL}CCI:       $cci25${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 25:   ${BLD}$title25a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title25b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title25c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity25${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

cached="$(grep -ir cache_credentials 2>/dev/null /etc/sssd/sssd.conf /etc/sssd/conf.d/)"

if [[ $cached ]]
then
  value="$(echo $cached | awk -F= '{print $2}' | sed 's/ //')" 
  if [[ $value == "true" && ${cached:0:1} != "#" ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}a. $cached${NORMAL}"
    limit="$(grep -ir offline_credentials_expiration 2>/dev/null /etc/sssd/sssd.conf /etc/sssd/conf.d/)"
    if [[ $limit ]]
    then
      value="$(echo $limit | awk -F= '{print $2}' | sed 's/ //')"
      if [[ $value == 1 ]]
      then
	fail=0
	echo -e "${NORMAL}RESULT:    ${BLD}b. $limit${NORMAL}"
      else
	echo -e "${NORMAL}RESULT:    ${RED}b. $limit${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    ${RED}b. Nothing returned${NORMAL}"
    fi
  elif [[ $value == "false" && ${cached:0:1} != "#" ]]
  then
    fail=2
    echo -e "${NORMAL}RESULT:    ${BLD}a. $cached\n           b. (skipping)${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${RED}a. $cached${NORMAL}"
  fi
else
  fail=2
  echo -e "${NORMAL}RESULT:    ${BLD}a. Nothing returned\n           b. (skipping)${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity25, $controlid, $stigid25, $ruleid25, $cci25, $datetime, ${GRN}PASSED, RHEL 9 prohibits the use of cached authenticators after one day.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity25, $controlid, $stigid25, $ruleid25, $cci25, $datetime, ${GRN}N/A, RHEL 9 sssd.service is not used. This requirement is Not Applicable.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity24, $controlid, $stigid24, $ruleid24, $cci24, $datetime, ${RED}FAILED, RHEL 9 does not map the authenticated identity to the user or group account for PKI-based authentication.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid26${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid26${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid26${NORMAL}"
echo -e "${NORMAL}CCI:       $cci26${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 26:   ${BLD}$title26a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title26b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title26c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity26${NORMAL}"

IFS='
'

fail=0

datetime="$(date +%FT%H:%M:%S)"

hash="$(cut -d: -f1,2 /etc/shadow | grep -Ev '\!|\*')"

if [[ $hash ]]
then
  for line in ${hash[@]}
  do
    user="$(echo $line | awk -F: '{print $1}')"
    pw="$(echo $line | awk -F: '{print $2}')"
    if [[ ${pw:0:3} == "\$6$" && $pw =~ "rounds=100000" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$user's password is FIPS 140-3 approved${NORMAL}"
    else
      fail=1
      echo -e "${NORMAL}RESULT:    ${RED}$user's password is not FIPS 140-3 approved${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}No interactive user accounts returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity26, $controlid, $stigid26, $ruleid26, $cci26, $datetime, ${GRN}PASSED, RHEL 9 employs FIPS 140-3 approved cryptographic hashing algorithms for all stored passwords.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity24, $controlid, $stigid24, $ruleid24, $cci24, $datetime, ${RED}FAILED, RHEL 9 does not employ FIPS 140-3 approved cryptographic hashing algorithms for all stored passwords.${NORMAL}"
fi

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid27${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid27${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid27${NORMAL}"
echo -e "${NORMAL}CCI:       $cci27${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 27:   ${BLD}$title27a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title27b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title27c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity27${NORMAL}"

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

uses="$(grep "^password.*pam_unix.so.*sha512" 2>/dev/null /etc/pam.d/password-auth)"

if [[ $uses ]]
then
  for line in ${uses[@]}
  do
    if [[ $line =~ "sha512" ]]
    then
      fail=0
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    else
      echo -e "${NORMAL}RESULT:    ${RED}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity27, $controlid, $stigid27, $ruleid27, $cci27, $datetime, ${GRN}PASSED, RHEL 9 pam_unix.so module is configured in the password-auth file to use a FIPS 140-3 approved cryptographic hashing algorithm for system authentication.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity24, $controlid, $stigid24, $ruleid24, $cci24, $datetime, ${RED}FAILED, RHEL 9 pam_unix.so module is not configured in the password-auth file to use a FIPS 140-3 approved cryptographic hashing algorithm for system authentication.${NORMAL}"
fi

exit
