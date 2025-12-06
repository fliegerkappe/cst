#! /bin/bash

# AC-11 Session Lock
# CONTROL: The information system:
# a. Prevents further access to the system by initiating a session lock after 
#    [Assignment: organization-defined time period] of inactivity or upon 
#    receiving a request from a user; and
# b. Retains the session lock until the user reestablishes access using established
#    identification and authentication procedures.

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

controlid="AC-11 Session Lock"

title1a="RHEL 9 must be able to initiate directly a session lock for all connection types using smartcard when the smartcard is removed."
title1b="Checking with: 'gsettings get org.gnome.settings-daemon.peripherals.smartcard removal-action'."
title1c="Expecting: ${YLO}'lock-screen'
           NOTE: If the result is not 'lock-screen', this is a finding."${BLD}
cci1="CCI-000056 CCI-000057 CCI-000058"
stigid1="RHEL-09-271045"
severity1="CAT II"
ruleid1="SV-258019r1045092"
vulnid1="V-258019"

title2a="RHEL 9 must prevent a user from overriding the disabling of the graphical user smart card removal action."
title2b="Checking with: 'gsettings writable org.gnome.settings-daemon.peripherals.smartcard removal-action'."
title2c="Expecting: ${YLO}false
           NOTE: If \"removal-action\" is writable and the result is \"true\", this is a finding.${BLD}"
cci2="CCI-000056 CCI-000057 CCI-000058"
stigid2="RHEL-09-271050"
severity2="CAT II"
ruleid2="SV-258020r1045094"
vulnid2="V-258020"


title3a="RHEL 9 must enable a user session lock until that user re-establishes access using established identification and authentication procedures for graphical user sessions."
title3b="Checking with: 'gsettings get org.gnome.desktop.screensaver lock-enabled'."
title3c="Expecting: ${YLO}true
           NOTE: This requirement assumes the use of the RHEL 9 default graphical user interface, Gnome Shell. If the system does not have any graphical user interface installed, this requirement is Not Applicable.
           NOTE: If the setting is \"false\", this is a finding."${BLD}
cci3="CCI-000056 CCI-000057 CCI-000058"
stigid3="RHEL-09-271055"
severity3="CAT II"
ruleid3="SV-258021r1015088"
vulnid3="V-258021"

title4a="RHEL 9 must prevent a user from overriding the screensaver lock-enabled setting for the graphical user interface."
title4b="Checking with 'gsettings writable org.gnome.desktop.screensaver lock-enabled'."
title4c="Expecting: ${YLO}false
           NOTE: This requirement assumes the use of the RHEL 9 default graphical user interface, Gnome Shell. If the system does not have any graphical user interface installed, this requirement is Not Applicable.
           NOTE: If \"lock-enabled\" is writable and the result is \"true\", this is a finding."${BLD}
cci4="CCI-000056 CCI-000057 CCI-000058"
stigid4="RHEL-09-271060"
severity4="CAT II"
ruleid4="SV-258022r1045097"
vulnid4="V-258022"

title5a="RHEL 9 must automatically lock graphical user sessions after 15 minutes of inactivity."
title5b="Checking with: 'gsettings get org.gnome.desktop.session idle-delay'."
title5c="Expecting: ${YLO}uint32 900
           NOTE: This requirement assumes the use of the RHEL 9 default graphical user interface, Gnome Shell. If the system does not have any graphical user interface installed, this requirement is Not Applicable.
           NOTE: If \"idle-delay\" is set to \"0\" or a value greater than \"900\", this is a finding."${BLD}
cci5="CCI-000057 CCI-000060"
stigid5="RHEL-09-271065"
severity5="CAT II"
ruleid5="SV-258023r958402"
vulnid5="V-258023"

title6a="RHEL 9 must prevent a user from overriding the session idle-delay setting for the graphical user interface."
title6b="Checking with 'gsettings writable org.gnome.desktop.session idle-delay'."
title6c="Expecting: ${YLO}false
           NOTE: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable."${BLD}
cci6="CCI-000057 CCI-000060"
stigid6="RHEL-09-271070"
severity6="CAT II"
ruleid6="SV-258024r1045100"
vulnid6="V-258024"

title7a="RHEL 9 must initiate a session lock for graphical user interfaces when the screensaver is activated."
title7b="Checking with: 'gsettings get org.gnome.desktop.screensaver lock-delay'."
title7c="Expecting: ${YLO}uint32 5 (or less)
           NOTE: This requirement assumes the use of the RHEL 9 default graphical user interface, Gnome Shell. If the system does not have any graphical user interface installed, this requirement is Not Applicable.
           NOTE: If the \"uint32\" setting is not \"5\" or less, or is missing, this is a finding."${BLD}
cci7="CCI-000057"
stigid7="RHEL-09-271075"
severity7="CAT II"
ruleid7="SV-258025r958402"
vulnid7="V-258025"

title8a="RHEL 9 must prevent a user from overriding the session lock-delay setting for the graphical user interface."
title8b="Checking with 'gsettings writable org.gnome.desktop.screensaver lock-delay'." 
title8c="Expecting: ${YLO}false
           NOTE: The example below is using the database \"local\" for the system, so the path is \"/etc/dconf/db/local.d\". This path must be modified if a database other than \"local\" is being used.
          NOTE: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable."${BLD}
cci8="CCI-000057"
stigid8="RHEL-09-271080"
severity8="CAT II"
ruleid8="SV-258026r1045103"
vulnid8="V-258026"

title9a="RHEL 9 must conceal, via the session lock, information previously visible on the display with a publicly viewable image."
title9b="Checking with: 'gsettings writable org.gnome.desktop.screensaver picture-uri'."
title9c="Expecting: ${YLO}false
           NOTE: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.
           NOTE: If \"picture-uri\" is writable and the result is \"true\", this is a finding."${BLD}
cci9="CCI-000060"
stigid9="RHEL-09-271085"
severity9="CAT II"
ruleid9="SV-258027r1045106"
vulnid9="V-258027"

title10a="RHEL 9 must automatically exit interactive command shell user sessions after 10 minutes of inactivity."
title10b="Checking with: 'grep -i tmout /etc/profile /etc/profile.d/*.sh'."
title10c="Expecting: ${YLO}/etc/profile.d/tmout.sh:declare -xr TMOUT=600
           NOTE: If \"TMOUT\" is not set to \"600\" or less in a script located in the \"/etc/'profile.d/\" directory, is missing or is commented out, this is a finding.
	   NOTE: The use of \"typeset\" is less common than, but synonymous with \"declare\". They are functionally the same."${BLD}
cci10="CCI-000057 CCI-001133"
stigid10="RHEL-09-412035"
severity10="CAT II"
ruleid10="SV-258068r1101950"
vulnid10="V-258068"

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

fail=1

datetime="$(date +%FT%H:%M:%S)"



removal="$(gsettings get org.gnome.settings-daemon.peripherals.smartcard removal-action)"
if [[ $removal == \'lock-screen\' ]]
then
  echo -e "${NORMAL}RESULT:    ${BLD}$removal${NORMAL}"
  fail=0
else
  echo -e "${NORMAL}RESULT:    ${RED}$removal${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${GRN}PASSED, RHEL 9 is able to initiate directly a session lock for all connection types using smart card when the smart card is removed.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${RED}FAILED, RHEL 9 is not able to initiate directly a session lock for all connection types using smart card when the smart card is removed.${NORMAL}"
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

IFS='
'

fail=1

datetime="$(date +%FT%H:%M:%S)"

isinstalled="$(dnf list --installed 2>/dev/null | grep gnome | egrep '(desktop|shell)')"

if [[ $isinstalled ]]
then	
  remaction="$(gsettings writable org.gnome.settings-daemon.peripherals.smartcard removal-action)"
  if [[ $remaction == false ]]
  then
    echo -e "${NORMAL}RESULT:    ${BLD}$remaction${NORMAL}"
    fail=0
  else
    echo -e "${NORMAL}RESULT:    ${RED}$remaction${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${BLD}Gnome is not installed${NORMAL}"
  fail=2
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}PASSED, RHEL 9 prevents a user from overriding the disabling of the graphical user smart card removal action.${NORMAL}"
elif [[ $fail == 2 ]]
then
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${GRN}N/A, The GNOME graphical user interface is not installed. This requirement is Not Applicable.${NORMAL}" 
else
  echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci1, $datetime, ${RED}FAILED, RHEL 9 does not prevent a user from overriding the disabling of the graphical user smart card removal action.${NORMAL}"
fi

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

fail=1

IFS='
'

isinstalled="$(dnf list --installed 2>/dev/null | grep gnome | egrep '(desktop|shell)')"

datetime="$(date +%FT%H:%M:%S)"

if [[ $isinstalled ]]
then
  enabled="$(gsettings get org.gnome.desktop.screensaver lock-enabled)"
  if [[ $enabled ]]
  then
    if [[ $enabled == "true" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$enabled${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}$enabled${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"lock-enabled\" is not configured.${NORMAL}"
  fi

  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}PASSED, RHEL 9 enables a user session lock until that user re-establishes access using established identification and authentication procedures for graphical user sessions.${NORMAL}"
  else
    echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${RED}FAILED, RHEL 9 does not enable a user session lock until that user re-establishes access using established identification and authentication procedures for graphical user sessions.${NORMAL}"
  fi

else
  echo -e "${NORMAL}RESULT:    ${BLD}GNOME is not installed${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${GRN}N/A, A graphical user interface is not installed.${NORMAL}"

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

fail=1

IFS='
'

isinstalled="$(dnf list --installed 2>/dev/null | grep gnome | egrep '(desktop|shell)')"

datetime="$(date +%FT%H:%M:%S)"

if [[ $isinstalled ]]
then
  enabled="$(gsettings writable org.gnome.desktop.screensaver lock-enabled)"
  if [[ $enabled ]]
  then
    if [[ $enabled == "false" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$enabled${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}$enabled${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"lock-enabled\" is not configured.${NORMAL}"
  fi

  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, RHEL 9 prevents a user from overriding the screensaver lock-enabled setting for the graphical user interface.${NORMAL}"
  else
    echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, RHEL 9 does not prevent a user from overriding the screensaver lock-enabled setting for the graphical user interface.${NORMAL}"
  fi

else
  echo -e "${NORMAL}RESULT:    ${BLD}GNOME server and client RPMs not found${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}N/A, GNOME is not installed${NORMAL}"
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

fail=1

IFS='
'

dir5="/etc/dconf/db/"
isinstalled="$(dnf list --installed 2>/dev/null | grep gnome | egrep '(desktop|shell)')"

datetime="$(date +%FT%H:%M:%S)"

if [[ $isinstalled ]]
then

  delay="$(gsettings get org.gnome.desktop.session idle-delay)"
  if [[ $delay ]]
  then
    idledelay="$(echo $delay | awk '{print $2}')"
    if (( $idledelay > 0 && $idledelay <= 900 ))
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$delay${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}$delay${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"idle-delay\" is not configured in $dir5/*.${NORMAL}"
  fi

  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}PASSED, RHEL 9 automatically locks graphical user sessions after 15 minutes of inactivity.${NORMAL}"
  else
    echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${RED}FAILED, RHEL 9 does not automatically lock graphical user sessions after 15 minutes of inactivity.${NORMAL}"
  fi

else
  echo -e "${NORMAL}RESULT:    ${BLD}GNOME server and client RPMs not found${NORMAL}"
  echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${GRN}N/A, GNOME is not installed${NORMAL}"
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

dir6="/etc/dconf/db"

fail=1

IFS='
'

isinstalled="$(dnf list --installed 2>/dev/null | grep gnome | egrep '(desktop|shell)')"

datetime="$(date +%FT%H:%M:%S)"

if [[ $isinstalled ]]
then
  delay="$(gsettings writable org.gnome.desktop.session idle-delay)"
  if [[ $delay ]]
  then
    if [[ $delay == "false" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$delay${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}$delay${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}idle-delay not defined in $dir6/*${NORMAL}"
  fi

  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}PASSED, RHEL 9 prevents a user from overriding the session idle-delay setting for the graphical user interface.${NORMAL}"
  else
    echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${RED}FAILED, RHEL 9 does not prevent a user from overriding the session idle-delay setting for the graphical user interface.${NORMAL}"
  fi

else
   echo -e "${NORMAL}RESULT:    ${BLD}GNOME server and client RPMs not found${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${GRN}N/A, GNOME is not installed${NORMAL}"
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

isinstalled="$(dnf list --installed 2>/dev/null | grep gnome | egrep '(desktop|shell)')"

datetime="$(date +%FT%H:%M:%S)"

if [[ $isinstalled ]]
then
  lockdelay="$(gsettings get org.gnome.desktop.screensaver lock-delay)"
  if [[ $lockdelay ]]
  then
    delayval="$(echo $lockdelay | awk '{print $2}')"
    if (( $delayval <= 5 ))
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$lockdelay${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}$lockdelay${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"lock-delay\" is not configured in \"org.gnome.desktop.screensaver\"${NORMAL}"
  fi

  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${GRN}PASSED, The operating system initiates a session lock for graphical user interfaces 5 seconds or less after the screensaver is activated.${NORMAL}"
  else
    echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${RED}FAILED, The operating system does not initiate a session lock for graphical user interfaces 5 seconds or less after the screensaver is activated.${NORMAL}"
  fi
  
else
   echo -e "${NORMAL}RESULT:    ${BLD}GNOME is not installed${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${GRN}N/A, GNOME is not installed.${NORMAL}"
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

isinstalled="$(dnf list --installed 2>/dev/null | grep gnome | egrep '(desktop|shell)')"

if [[ $isinstalled ]]
then
  lockdelay="$(gsettings writable org.gnome.desktop.screensaver lock-delay)"
  if [[ $lockdelay ]]
  then
    if [[ $lockdelay == "false" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$lockdelay${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}$lockdelay${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"lock-delay\" is not configured in \"org.gnome.desktop.screensaver\"${NORMAL}"
  fi

  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${GRN}PASSED, RHEL 9 prevents a user from overriding the session lock-delay setting for the graphical user interface.${NORMAL}"
  else
    echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${RED}FAILED, RHEL 9 does not prevent a user from overriding the session lock-delay setting for the graphical user interface.${NORMAL}"
  fi

else
   echo -e "${NORMAL}RESULT:    ${BLD}GNOME is not installed${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${GRN}N/A, GNOME is not installed.${NORMAL}"
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

fail=1

IFS='
'

datetime="$(date +%FT%H:%M:%S)"

isinstalled="$(dnf list --installed 2>/dev/null | grep gnome | egrep '(desktop|shell)')"

if [[ $isinstalled ]]
then
  picuri="$(gsettings writable org.gnome.desktop.screensaver picture-uri)"
  if [[ $picuri ]]
  then
    if [[ $picuri == "false" ]]
    then
      echo -e "${NORMAL}RESULT:    ${BLD}$picuri${NORMAL}"
      fail=0
    else
      echo -e "${NORMAL}RESULT:    ${RED}$picuri${NORMAL}"
    fi
  else
    echo -e "${NORMAL}RESULT:    ${RED}\"picture-uri\" is not configured in \"org.gnome.desktop.screensaver\"${NORMAL}"
  fi

  if [[ $fail == 0 ]]
  then
    echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${GRN}PASSED, RHEL 9 conceals via the session lock information previously visible on the display with a publicly viewable image.${NORMAL}"
  else
    echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${RED}FAILED, RHEL 9 does not conceal via the session lock information previously visible on the display with a publicly viewable image.${NORMAL}"
  fi

else
   echo -e "${NORMAL}RESULT:    ${BLD}GNOME is not installed${NORMAL}"
   echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid9, $cci9, $datetime, ${GRN}N/A, GNOME is not installed.${NORMAL}"
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

timeout="$(grep -i tmout /etc/profile /etc/profile.d/*.sh | grep -v '#' )"

if [[ $timeout ]]
then
  for line in ${timeout[@]}
  do
    if [[ $line =~ "declare" || $line =~ "typeset" ]]
    then
      file="$(echo $timeout | awk -F: '{print $1}')"
      setting="$(echo $timeout | awk -F: '{print $2}')"
      period="$(echo $line | awk -F= '{print $2}')"
      if (( $period <= 600 && $period > 0 ))
      then
	fail=0
        echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
        fail=0
      else
        echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$setting${NORMAL}"
      fi
    else
      echo -e "${NORMAL}RESULT:    ${BLD}$line${NORMAL}"
    fi
  done
else
  echo -e "${NORMAL}RESULT:    ${BLD}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${GRN}PASSED, RHEL 9 automatically exits interactive command shell user sessions after at most 10 minutes of inactivity.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${RED}FAILED, RHEL 9 does not automatically exit interactive command shell user sessions after at most 10 minutes of inactivity.${NORMAL}"
fi

exit
