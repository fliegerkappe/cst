#! /bin/bash

# MA-4 Nonlocal Maintenance

# CONTROL: 
# a. Approve and monitor nonlocal maintenance and diagnostic activities;
# b. Allow the use of nonlocal maintenance and diagnostic tools only as consistent
#    with organizational policy and documented in the security plan for the system;
# c. Employ strong authentication in the establishment of nonlocal maintenance and
#    diagnostic sessions;
# d. Maintain records for nonlocal maintenance and diagnostic activities; and
# e. Terminate session and network connections when nonlocal maintenance is completed.

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

controlid="MA-4 Nonlocal Maintenance"

title1a="RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /var/log/tallylog."
title1b="Checking with: auditctl -l | grep /var/log/tallylog"
title1c="Expecting: ${YLO}-w /var/log/tallylog -p wa -k logins
           NOTE: If the command does not return a line, or the line is commented out, is a finding."${BL}
cci1="CCI-000172 CCI-002884"
stigid1="RHEL-09-654260"
severity1="CAT II"
ruleid1="SV-258226r958846"
vulnid1="V-258226"

title2a="RHEL 9 must enable FIPS mode."
title2b="Checking with: fips-mode-setup --check"
title2c="Expecting: ${YLO}FIPS mode is enabled.
           NOTE: If FIPS mode is not enabled, this is a finding."
cci2="CCI-000068 CCI-000877 CCI-002418 CCI-002450"
stigid2="RHEL-09-671010"
severity2="CAT I"
ruleid2="SV-258230r958408"
vulnid2="V-258230"

title3a="RHEL 9 must enable auditing of processes that start prior to the audit daemon."
title3b="Checking with: 
           a. grubby --info=ALL | grep args | grep -v 'audit=1'
	   b. grep audit /etc/default/grub"
title3c="Expecting: ${YLO}
           a. Nothing returned
	   b. GRUB_CMDLINE_LINUX=\"audit=1\"
	   NOTE: a. If any output is returned, this is a finding.
	   NOTE: b. If \"audit\" is not set to \"1\", is missing, or is commented out, this is a finding."${BLD}
cci3="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-001464 CCI-002884"
stigid3="RHEL-09-212055"
severity3="CAT III"
ruleid3="SV-257796r1044847"
vulnid3="V-257796"

title4a="RHEL 9 must enable the Pluggable Authentication Module (PAM) interface for SSHD."
title4b="Checking with: /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print \$4}' | tr -d '\\\\r' | tr '\\\\n' ' ' | grep -iH '^\s*usepam'"
title4c="Expecting: ${YLO}UsePAM yes
           NOTE: If the \"UsePAM\" keyword is set to \"no\", is missing, or is commented out, this is a finding."${BLD}
cci4="CCI-000877"
stigid4="RHEL-09-255050"
severity4="CAT I"
ruleid4="SV-257986r1045030"
vulnid4="V-257986"

title5a="RHEL 9 must be configured so that all network connections associated with SSH traffic are terminated after 10 minutes of becoming unresponsive."
title5b="Checking with: /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print \$4}' | tr -d '\\\\r' | tr '\\\\n' ' ' | xargs grep -iH '^\s*clientaliveinterval'"
title5c="Expecting: ${YLO}ClientAliveInterval 600
           NOTE: If \"ClientAliveInterval\" does not exist, does not have a value of \"600\" or less in \"/etc/ssh/sshd_config\", or is commented out, this is a finding."${BLD}
cci5="CCI-001133 CCI-002361 CCI-002891"
stigid5="RHEL-09-255100"
severity5="CAT II"
ruleid5="SV-257996r1045055"
vulnid5="V-257996"

title6a="RHEL 9 audit package must be installed."
title6b="Checking with: dnf list --installed audit"
title6c="Expecting: ${YLO}audit-3.0.7-101.el9_0.2.x86_64
           NOTE: If the \"audit\" package is not installed, this is a finding."${BLD}
cci6="CCI-000130 CCI-000131 CCI-000132 CCI-000133 CCI-000134 CCI-000135 CCI-000154 CCI-000158 CCI-000159 CCI-000169 CCI-000172 CCI-001464 CCI-001487 CCI-003938 CCI-001875 CCI-001876 CCI-001877 CCI-001878 CCI-001879 CCI-001880 CCI-001881 CCI-001882 CCI-001889 CCI-001914 CCI-002884 CCI-001814"
stigid6="RHEL-09-653010"
severity6="CAT II"
ruleid6="SV-258151r1045298"
vulnid6="V-258151"

title7a="RHEL 9 audit service must be enabled."
title7b="Checking with: systemctl status auditd.service"
title7c="Expecting: ${YLO}
           auditd.service - Security Auditing Service
           Loaded:loaded (/usr/lib/systemd/system/auditd.service; enabled; vendor preset: enabled)
           Active: active (running) since Tues 2022-05-24 12:56:56 EST; 4 weeks 0 days ago
           NOTE: If the audit service is not \"active\" and \"running\", this is a finding."${BLD}
cci7="CCI-000130 CCI-000131 CCI-000132 CCI-000133 CCI-000134 CCI-000135 CCI-000154 CCI-000158 CCI-000159 CCI-000169 CCI-000172 CCI-001464 CCI-001487 CCI-003938 CCI-001875 CCI-001876 CCI-001877 CCI-001878 CCI-001879 CCI-001880 CCI-001881 CCI-001882 CCI-001889 CCI-001914 CCI-002884 CCI-001814"
stigid7="RHEL-09-653015"
severity7="CAT II"
ruleid7="SV-258152r1015127" 
vulnid7="V-258152"

title8a="RHEL 9 must audit all uses of the chmod, fchmod, and fchmodat system calls."
title8b="Checking with: auditctl -l | grep chmod"
title8c="Expecting: ${YLO}
           -a always,exit -S arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod
           -a always,exit -S arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod
           NOTE: If both the \"b32\" and \"b64\" audit rules are not defined for the \"chmod\", \"fchmod\", and \"fchmodat\" system calls, this is a finding."${BLD}
cci8="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid8="RHEL-09-654015"
severity8="CAT II"
ruleid8="SV-258177r1106368"
vulnid8="V-258177"

title9a="RHEL 9 must audit all uses of the chown, fchown, fchownat, and lchown system calls."
title9b="Checking with: auditctl -l | grep chown"
title9c="Expecting: ${YLO}
           -a always,exit -S arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod
           -a always,exit -S arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod
           NOTE: If both the \"b32\" and \"b64\" audit rules are not defined for the \"chown\", \"fchown\", \"fchownat\", and \"lchown\" system calls, this is a finding."${BLD}
cci9="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid9="RHEL-09-654020"
severity9="CAT II"
ruleid9="SV-258178r1106370"
vulnid9="V-258178"

title10a="RHEL 9 must audit all uses of the setxattr, fsetxattr, lsetxattr, removexattr, fremovexattr, and lremovexattr system calls."
title10b="Checking with: auditctl -l | grep xattr"
title10c="Expecting: ${YLO}
           -a always,exit -S arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod
           -a always,exit -S arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod
           -a always,exit -S arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid=0 -F key=perm_mod
           -a always,exit -S arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid=0 -F key=perm_mod
           NOTE: If both the \"b32\" and \"b64\" audit rules are not defined for the \"setxattr\", \"fsetxattr\", \"lsetxattr\", \"removexattr\", \"fremovexattr\", and \"lremovexattr\" system calls, or any of the lines returned are commented out, this is a finding."${BLD}
cci10="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid10="RHEL-09-654025"
severity10="CAT II"
ruleid10="SV-258179r1106371"
vulnid10="V-258179"

title11a="RHEL 9 must audit all uses of umount system calls."
title11b="Checking with: auditctl -l | grep /usr/bin/umount"
title11c="Expecting: ${YLO}
-a always,exit -S all -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-mount
NOTE: If the command does not return an audit rule for \"umount\" or any of the lines returned are commented out, this is a finding."${BLD}
cci11="CCI-000130 CCI-000169 CCI-000172 CCI-002884"
stigid11="RHEL-09-654030"
severity11="CAT II"
ruleid11="SV-258180r1045325"
vulnid11="V-258180"

title12a="RHEL 9 must audit all uses of the chacl command."
title12b="Checking with: auditctl -l | grep chacl"
title12c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_mod
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci12="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid12="RHEL-09-654035"
severity12="CAT II"
ruleid12="SV-258181r1045328"
vulnid12="V-258181"

title13a="RHEL 9 must audit all uses of the setfacl command."
title13b="Checking with: auditctl -l | grep setfacl"
title13c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_mod
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci13="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid13="RHEL-09-654040"
severity13="CAT II"
ruleid13="SV-258182r1045331"
vulnid13="V-258182"

title14a="RHEL 9 must audit all uses of the chcon command."
title14b="Checking with: auditctl -l | grep chcon"
title14c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_mod
	   NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci14="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid14="RHEL-09-654045"
severity14="CAT II"
ruleid14="SV-258183r1045334"
vulnid14="V-258183"

title15a="RHEL 9 must audit all uses of the semanage command."
title15b="Checking with: auditctl -l | grep semanage"
title15c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/sbin/semanage -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-unix-update
	   NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci15="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid15="RHEL-09-654050"
severity15="CAT II"
ruleid15="SV-258184r1045337"
vulnid15="V-258184"

title16a="RHEL 9 must audit all uses of the setfiles command."
title16b="Checking with: auditctl -l | grep setfiles"
title16c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/sbin/setfiles -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-unix-update
	   NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci16="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid16="RHEL-09-654055"
severity16="CAT II"
ruleid16="SV-258185r1045340"
vulnid16="V-258185"

title17a="RHEL 9 must audit all uses of the setsebool command."
title17b="Checking with: auditctl -l | grep setsebool"
title17c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/sbin/setsebool -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged
	   NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci17="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid17="RHEL-09-654060"
severity17="CAT II"
ruleid17="SV-258186r1045343"
vulnid17="V-258186"

title18a="RHEL 9 must audit all uses of the rename, unlink, rmdir, renameat, and unlinkat system calls."
title18b="Checking with: auditctl -l | grep 'rename\|unlink\|rmdir'"
title18c="Expecting: ${YLO}
-a always,exit -S arch=b32 -S unlink,rename,rmdir,unlinkat,renameat -F auid>=1000 -F auid!=-1 -F key=delete
-a always,exit -S arch=b64 -S rename,rmdir,unlink,unlinkat,renameat -F auid>=1000 -F auid!=-1 -F key=delete
NOTE: If the command does not return an audit rule for \"rename\", \"unlink\", \"rmdir\", \"renameat\", and \"unlinkat\" or any of the lines returned are commented out, this is a finding."${BLD}
cci18="CCI-000130 records. CCI-000169 CCI-000172 CCI-002884"
stigid18="RHEL-09-654065"
severity18="CAT II"
ruleid18="SV-258187r1106373"
vulnid18="V-258187"

title19a="RHEL 9 must audit all uses of the truncate, ftruncate, creat, open, openat, and open_by_handle_at system calls."
title19b="Checking with: auditctl -l | grep 'open\i\\\b\|openat\|open_by_handle_at\|truncate\|creat'"
title19c="Expecting: ${YLO}
           -a always,exit -S arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -S auid!=-1 -F key=perm_access
           -a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -S auid!=-1 -F key=perm_access
           -a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -S auid!=-1 -F key=perm_access
           -a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -S auid!=-1 -F key=perm_access
           NOTE: If the output does not produce rules containing \"-F exit=-EPERM\", this is a finding.
           NOTE: If the output does not produce rules containing \"-F exit=-EACCES\", this is a finding.
           NOTE: If the command does not return an audit rule for \"truncate\", \"ftruncate\", \"creat\", \"open\", \"openat\", and \"open_by_handle_at\" or any of the lines returned are commented out, this is a finding."${BLD}
cci19="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid19="RHEL-09-654070"
severity19="CAT II"
ruleid19="SV-258188r1106375"
vulnid19="V-258188"

title20a="RHEL 9 must audit all uses of the delete_module system call."
title20b="Checking with: auditctl -l | grep delete_module"
title20c="Expecting: ${YLO}
-a always,exit -S arch=b32 -S delete_module -F auid>=1000 -F auid!=-1 -F key=module_chng
-a always,exit -S arch=b64 -S delete_module -F auid>=1000 -F auid!=-1 -F key=module_chng
NOTE: If both the \"b32\" and \"b64\" audit rules are not defined for the \"delete_module\" system call, or any of the lines returned are commented out, this is a finding."${BLD}
cci20="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid20="RHEL-09-654075"
severity20="CAT II"
ruleid20="SV-258189r1106377"
vulnid20="V-258189"

title21a="RHEL 9 must audit all uses of the init_module and finit_module system calls."
title21b="Checking with: auditctl -l | grep init_module"
title21c="Expecting: ${YLO}
           -a always,exit -S arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -F key=module_chng
           -a always,exit -S arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -F key=module_chng
	   NOTE: If both the \"b32\" and \"b64\" audit rules are not defined for the \"init_module\" system call, or any of the lines returned are commented out, this is a finding."${BLD}
cci21="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid21="RHEL-09-654080"
severity21="CAT II"
ruleid21="SV-258190r1106379"
vulnid21="V-258190"

title22a="RHEL 9 must audit all uses of the chage command."
title22b="Checking with: auditctl -l | grep chage"
title22c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-chage
	   NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci22="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid22="RHEL-09-654085"
severity22="CAT II"
ruleid22="SV-258191r1045358"
vulnid22="V-258191"

title23a="RHEL 9 must audit all uses of the chsh command."
title23b="Checking with: auditctl -l | grep chsh"
title23c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd
	   NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci23="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid23="RHEL-09-654090"
severity23="CAT II"
ruleid23="SV-258192r1045361"
vulnid23="V-258192"

title24a="RHEL 9 must audit all uses of the crontab command."
title24b="Checking with: auditctl -l | grep crontab"
title24c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-crontab
	   NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci24="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid24="RHEL-09-654095"
severity24="CAT II"
ruleid24="SV-258193r1045364"
vulnid24="V-258193"

title25a="RHEL 9 must audit all uses of the gpasswd command."
title25b="Checking with: auditctl -l | grep gpasswd"
title25c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-gpasswd
	   NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci25="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid25="RHEL-09-654100"
severity25="CAT II"
ruleid25="SV-258194r1045367"
vulnid25="V-258194"

title26a="RHEL 9 must audit all uses of the kmod command."
title26b="Checking with: auditctl -l | grep kmod"
title26c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=-1 -F key=modules
	   NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci26="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid26="RHEL-09-654105"
severity26="CAT II"
ruleid26="SV-258195r1045370"
vulnid26="V-258195"

title27a="RHEL 9 must audit all uses of the newgrp command."
title27b="Checking with: auditctl -l | grep newgrp"
title27c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd
	   NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci27="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid27="RHEL-09-654110"
severity27="CAT II"
ruleid27="SV-258196r1045373"
vulnid27="V-258196"

title28a="RHEL 9 must audit all uses of the pam_timestamp_check command."
title28b="Checking with: auditctl -l | grep timestamp"
title28c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-pam_timestamp_check
	   NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci28="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid28="RHEL-09-654115"
severity28="CAT II"
ruleid28="SV-258197r1045376"
vulnid28="V-258197"

title29a="RHEL 9 must audit all uses of the passwd command."
title29b="Checking with: auditctl -l | egrep '(/usr/bin/passwd)'"
title29c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-passwd
	   NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci29="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid29="RHEL-09-654120"
severity29="CAT II"
ruleid29="SV-258198r1045379"
vulnid29="V-258198"

title30a="RHEL 9 must audit all uses of the postdrop command."
title30b="Checking with: auditctl -l | grep postdrop"
title30c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/sbin/postdrop -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-unix-update
	   NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci30="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid30="RHEL-09-654125"
severity30="CAT II"
ruleid30="SV-258199r1045382"
vulnid30="V-258199"

title31a="RHEL 9 must audit all uses of the postqueue command."
title31b="Checking with: auditctl -l | grep postque"
title31c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/sbin/postqueue -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-unix-update
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci31="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid31="RHEL-09-654130"
severity31="CAT II"
ruleid31="SV-258200r1045385"
vulnid31="V-258200"

title32a="RHEL 9 must audit all uses of the ssh-agent command."
title32b="Checking with: auditctl -l | grep ssh-agent"
title32c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-ssh
	   NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci32="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid32="RHEL-09-654135"
severity32="CAT II"
ruleid32="SV-258201r1045388"
vulnid32="V-258201"

title33a="RHEL 9 must audit all uses of the ssh-keysign command."
title33b="Checking with: auditctl -l | grep ssh-keysign"
title33c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-ssh
	   NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci33="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid33="RHEL-09-654140"
severity33="CAT II"
ruleid33="SV-258202r1045391"
vulnid33="V-258202"

title34a="RHEL 9 must audit all uses of the su command."
title34b="Checking with: auditctl -l | grep '/usr/bin/su\\\\b'"
title34c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-priv_change
	   NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci34="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid34="RHEL-09-654145"
severity34="CAT II"
ruleid34="SV-258203r1045394"
vulnid34="V-258203"

title35a="RHEL 9 must audit all uses of the sudo command."
title35b="Checking with: auditctl -l | grep '/usr/bin/sudo\\\\b'"
title35c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd
	   NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci35="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid35="RHEL-09-654150"
severity35="CAT II"
ruleid35="SV-258204r1045397"
vulnid35="V-258204"

title36a="RHEL 9 must audit all uses of the sudoedit command."
title36b="Checking with: auditctl -l | grep /usr/bin/sudoedit"
title36c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd
	   NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci36="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid36="RHEL-09-654155"
severity36="CAT II"
ruleid36="SV-258205r1045400"
vulnid36="V-258205"

title37a="RHEL 9 must audit all uses of the unix_chkpwd command."
title37b="Checking with: auditctl -l | grep unix_chkpwd"
title37c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-unix-update
	   NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci37="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid37="RHEL-09-654160"
severity37="CAT II"
ruleid37="SV-258206r1045403"
vulnid37="V-258206"

title38a="RHEL 9 must audit all uses of the unix_update command."
title38b="Checking with: auditctl -l | grep unix_updat"
title38c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/sbin/unix_update -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-unix-update
	   NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci38="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid38="RHEL-09-654165"
severity38="CAT II"
ruleid38="SV-258207r1045406"
vulnid38="V-258207"

title39a="RHEL 9 must audit all uses of the userhelper command."
title39b="Checking with: auditctl -l | grep userhelper"
title39c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/sbin/userhelper -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-unix-update
	   NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci39="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid39="RHEL-09-654170"
severity39="CAT II"
ruleid39="SV-258208r1045409"
vulnid39="V-258208"

title40a="RHEL 9 must audit all uses of the usermod command."
title40b="Checking with: auditctl -l | grep usermod"
title40c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-usermod
	   NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci40="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid40="RHEL-09-654175"
severity40="CAT II"
ruleid40="SV-258209r1045412"
vulnid40="V-258209"

title41a="RHEL 9 must audit all uses of the mount command."
title41b="Checking with: auditctl -l | grep /usr/bin/mount"
title41c="Expecting: ${YLO}
           -a always,exit -S all -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-mount
	   NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci41="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid41="RHEL-09-654180"
severity41="CAT II"
ruleid41="SV-258210r1045415"
vulnid41="V-258210"

title42a="Successful/unsuccessful uses of the umount system call in RHEL 9 must generate an audit record."
title42b="Checking with: auditctl -l | grep b32 | grep 'umount\\\\b'"
title42c="Expecting: ${YLO}
           -a always,exit -S arch=b32 -S umount -F auid>=1000 -F auid!=-1 -F key=privileged-umount
	   NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci42="CCI-000130 CCI-000169 CCI-000172 CCI-002884"
stigid42="RHEL-09-654205"
severity42="CAT II"
ruleid42="SV-258215r1106381"
vulnid42="RHEL-09-654210V-258215"

title43a="Successful/unsuccessful uses of the umount2 system call in RHEL 9 must generate an audit record."
title43b="Checking with: auditctl -l | grep umount2"
title43c="Expecting: ${YLO}
           -a always,exit -S arch=b64 -S umount2 -F auid>=1000 -F auid!=-1 -F key=privileged-umount
           -a always,exit -S arch=b32 -S umount2 -F auid>=1000 -F auid!=-1 -F key=privileged-umount
           NOTE: If no line is returned, this is a finding."${BLD}
cci43="CCI-000130 CCI-000169 CCI-000172 CCI-002884"
stigid43="RHEL-09-654210"
severity43="CAT II"
ruleid43="SV-258216r1102090"
vulnid43="V-258216"

title44a="RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/sudoers."
title44b="Checking with: auditctl -l | grep '/etc/sudoers[^.]'"
title44c="Expecting: ${YLO}-w /etc/sudoers -p wa -k identity
           If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci44="CCI-000018 CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-001403 CCI-001404 CCI-001405 CCI-002130 CCI-000015 CCI-002884 CCI-002132"
stigid44="RHEL-09-654215"
severity44="CAT II"
ruleid44="SV-258217r1045436"
vulnid44="V-258217"

title45a="RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/sudoers.d/ directory."
title45b="Checking with: auditctl -l | grep /etc/sudoers.d"
title45c="Expecting: ${YLO}-w /etc/sudoers.d/ -p wa -k identity
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci45="CCI-000018 CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-001403 CCI-001404 CCI-001405 CCI-002130 CCI-000015 CCI-002884 CCI-002132"
stigid45="RHEL-09-654220"
severity45="CAT II"
ruleid45="SV-258218r1101981"
vulnid45="V-258218"

title46a="RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/group."
title46b="Checking with: auditctl -l | egrep '(/etc/group)'"
title46c="Expecting: ${YLO}-w /etc/group -p wa -k identity
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci46="CCI-000018 CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-001403 CCI-001404 CCI-001405 CCI-002130 CCI-000015 CCI-002884 CCI-002132"
stigid46="RHEL-09-654225"
severity46="CAT II"
ruleid46="SV-258219r1015130"
vulnid46="V-258219"

title47a="RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/gshadow."
title47b="Checking with: auditctl -l | egrep '(/etc/gshadow)'"
title47c="Expecting: ${YLO}-w /etc/gshadow -p wa -k identity
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci47="CCI-000018 CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-001403 CCI-001404 CCI-001405 CCI-002130 CCI-000015 CCI-002884 CCI-002132"
stigid47="RHEL-09-654230"
severity47="CAT II"
ruleid47="SV-258220r1015131"
vulnid47="V-258220"

title48a="RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/opasswd."
title48b="Checking with: auditctl -l | egrep '(/etc/security/opasswd)'"
title48c="Expecting: ${YLO}-w /etc/security/opasswd -p wa -k identity
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci48="CCI-000018 CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-001403 CCI-001404 CCI-001405 CCI-002130 CCI-000015 CCI-002884 CCI-002132"
stigid48="RHEL-09-654235"
severity48="CAT II"
ruleid48="SV-258221r1015132"
vulnid48="V-258221"

title49a="RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd."
title49b="Checking with: auditctl -l | egrep '(/etc/passwd)'"
title49c="Expecting: ${YLO}-w /etc/passwd -p wa -k identity
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci49="CCI-000015 CCI-000018 CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-001403 CCI-001404 CCI-001405 CCI-002130 CCI-002884 CCI-001683 CCI-001684 CCI-001685 CCI-001686 CCI-002132"
stigid49="RHEL-09-654240"
severity49="CAT II"
ruleid49="SV-258222r1015133"
vulnid49="V-258222"

title50a="RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow."
title50b="Checking with: auditctl -l | egrep '(/etc/shadow)'"
title50c="Expecting: ${YLO}-w /etc/shadow -p wa -k identity
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci50="CCI-000018 CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-001403 CCI-001404 CCI-001405 CCI-002130 CCI-000015 CCI-002884 CCI-002132"
stigid50="RHEL-09-654245"
severity50="CAT II"
ruleid50="SV-258223r1015134"
vulnid50="V-258223"

title51a="RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /var/log/faillock."
title51b="Checking with: auditctl -l | grep /var/log/faillock"
title51c="Expecting: ${YLO}-w /var/log/faillock -p wa -k logins
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci51="CCI-000172 CCI-002884"
stigid51="RHEL-09-654250"
severity51="CAT II"
ruleid51="SV-258224r1014988"
vulnid51="V-258224"

title52a="RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /var/log/lastlog."
title52b="Checking with: auditctl -l | grep /var/log/lastlog"
title52c="Expecting: ${YLO}-w /var/log/lastlog -p wa -k logins
           NOTE: If the command does not return a line, or the line is commented out, this is a finding."${BLD}
cci52="CCI-000130 CCI-000135 CCI-000169 CCI-000172 CCI-002884"
stigid52="RHEL-09-654255"
severity52="CAT II"
ruleid52="SV-258225r1014990"
vulnid52="V-258225"

title53a="RHEL 9 must have the crypto-policies package installed."
title53b="Checking with: dnf list --installed crypto-policies"
title53c="Expecting: ${YLO}crypto-policies.noarch          20240828-2.git626aa59.el9_5
           NOTE: If the crypto-policies package is not installed, this is a finding."${BLD}
cci53="CCI-002450 CCI-002890 CCI-003123"
stigid53="RHEL-09-215100"
severity53="CAT II"
ruleid53="SV-258234r1051250"
vulnid53="V-258234"

title54a="RHEL 9 cryptographic policy must not be overridden."
title54b="Checking with: 
           a. update-crypto-policies --check
	   b. ls -l /etc/crypto-policies/back-ends/"
title54c="Expecting: ${YLO}
           a. The configured policy matches the generated policy
	   b. lrwxrwxrwx. 1 root root  40 Nov 13 16:29 bind.config -> /usr/share/crypto-policies/FIPS/bind.txt
           b. lrwxrwxrwx. 1 root root  42 Nov 13 16:29 gnutls.config -> /usr/share/crypto-policies/FIPS/gnutls.txt
              ...
	      ...
	   b. lrwxrwxrwx. 1 root root  48 Nov 13 16:29 openssl_fips.config -> /usr/share/crypto-policies/FIPS/openssl_fips.txt
           NOTE: a. If the returned message does not match the above, but instead matches the following, this is a finding:
	   NOTE: b. If the paths do not point to the respective files under /usr/share/crypto-policies/FIPS path, this is a finding.
	   NOTE: If there is an operational need to use a subpolicy that causes the links to the crypto backends to break, this is a finding, and exceptions will need to be made by the authorizing official (AO) and documented with the information system security officer (ISSO)."${BLD}
cci54="CCI-002450 CCI-002890 CCI-003123"
stigid54="RHEL-09-672020"
severity54="CAT I"
ruleid54="SV-258236r1101920"
vulnid54="V-258236"

title55a="RHEL 9 must implement a FIPS 140-3-compliant systemwide cryptographic policy."
title55b="Checking with: update-crypto-policies --show"
title55c="Expecting: ${YLO}FIPS
           NOTE: If the systemwide crypto policy is not set to \"FIPS\", this is a finding."${BLD}
cci55="CCI-002450 CCI-002890 CCI-003123"
stigid55="RHEL-09-215105"
severity55="CAT II"
ruleid55="SV-258241r1106302"
vulnid55="V-258241"

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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity1, $controlid, $stigid1, $ruleid1, $cci1, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258226)${NORMAL}"

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

echo -e "${NORMAL}$hostname, $severity2, $controlid, $stigid2, $ruleid2, $cci2, $datetime, ${CYN}VERIFY, (See AC-17 Remote Access: V-258230)${NORMAL}"

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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity3, $controlid, $stigid3, $ruleid3, $cci3, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-257796)${NORMAL}"

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

fail=1

datetime="$(date +%FT%H:%M:%S)"

usepam="$(/usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs grep -iH '^\s*usepam')"

if [[ $usepam ]]
then
  file="$(echo $usepam | awk -F: '{print $1}')"
  setting="$(echo $usepam | awk -F: '{print $2}')"
  value="$(echo $setting | awk '{print $2}' | sed 's/ //')"
  if [[ $value == "yes" && ${setting:0:1} != "#" ]]
  then
    fail=0
    echo -e "${NORMAL}RESULT:    ${CYN}$file:${BLD}$setting${NORMAL}"
  else
    echo -e "${NORMAL}RESULT:    ${CYN}$file:${RED}$setting${NORMAL}"
  fi
else
  echo -e "${NORMAL}RESULT:    ${RED}Nothing returned${NORMAL}"
fi

if [[ $fail == 0 ]]
then
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${GRN}PASSED, RHEL 9 enables the Pluggable Authentication Module (PAM) interface for SSHD.${NORMAL}"
else
  echo -e "${NORMAL}$hostname, $severity4, $controlid, $stigid4, $ruleid4, $cci4, $datetime, ${RED}FAILED, RHEL 9 does not enable the Pluggable Authentication Module (PAM) interface for SSHD.${NORMAL}"
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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity5, $controlid, $stigid5, $ruleid5, $cci5, $datetime, ${CYN}VERIFY, (See AC-12 Session Termination: V-257996)${NORMAL}"

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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity6, $controlid, $stigid6, $ruleid6, $cci6, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258151)${NORMAL}"

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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity7, $controlid, $stigid7, $ruleid7, $cci7, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258152)${NORMAL}"

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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity8, $controlid, $stigid8, $ruleid8, $cci8, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258177)${NORMAL}"

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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity9, $controlid, $stigid9, $ruleid8, $cci9, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258178)${NORMAL}"

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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity10, $controlid, $stigid10, $ruleid10, $cci10, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258179)${NORMAL}"

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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity11, $controlid, $stigid11, $ruleid11, $cci11, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258180)${NORMAL}"

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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity12, $controlid, $stigid12, $ruleid12, $cci12, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258181)${NORMAL}"

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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity13, $controlid, $stigid13, $ruleid13, $cci13, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258182)${NORMAL}"

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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity14, $controlid, $stigid14, $ruleid14, $cci14, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258183)${NORMAL}"

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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity15, $controlid, $stigid15, $ruleid15, $cci15, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258184)${NORMAL}"

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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity16, $controlid, $stigid16, $ruleid16, $cci16, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258185)${NORMAL}"

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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity17, $controlid, $stigid17, $ruleid17, $cci17, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258186)${NORMAL}"

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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity18, $controlid, $stigid18, $ruleid18, $cci18, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258187)${NORMAL}"

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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity19, $controlid, $stigid19, $ruleid19, $cci19, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258188)${NORMAL}"

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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity20, $controlid, $stigid20, $ruleid20, $cci20, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258189)${NORMAL}"

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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity21, $controlid, $stigid21, $ruleid21, $cci21, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258190)${NORMAL}"

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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity22, $controlid, $stigid22, $ruleid22, $cci22, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258191)${NORMAL}"

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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity23, $controlid, $stigid23, $ruleid23, $cci23, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258192)${NORMAL}"

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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity24, $controlid, $stigid24, $ruleid24, $cci24, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258193)${NORMAL}"

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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity25, $controlid, $stigid25, $ruleid25, $cci25, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258194)${NORMAL}"

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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity26, $controlid, $stigid26, $ruleid26, $cci26, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258195)${NORMAL}"

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

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity27, $controlid, $stigid27, $ruleid27, $cci27, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258196)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid28${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid28${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid28${NORMAL}"
echo -e "${NORMAL}CCI:       $cci28${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 28:   ${BLD}$title28a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title28b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title28c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity28${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity28, $controlid, $stigid28, $ruleid28, $cci28, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258197)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid29${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid29${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid29${NORMAL}"
echo -e "${NORMAL}CCI:       $cci29${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 29:   ${BLD}$title29a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title29b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title29c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity29${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity29, $controlid, $stigid29, $ruleid29, $cci29, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258198)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid30${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid30${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid30${NORMAL}"
echo -e "${NORMAL}CCI:       $cci30${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 30:   ${BLD}$title30a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title30b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title30c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity30${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity30, $controlid, $stigid30, $ruleid30, $cci30, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258199)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid31${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid31${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid31${NORMAL}"
echo -e "${NORMAL}CCI:       $cci31${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 31:   ${BLD}$title31a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title31b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title31c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity31${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity31, $controlid, $stigid31, $ruleid31, $cci31, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258200)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid32${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid32${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid32${NORMAL}"
echo -e "${NORMAL}CCI:       $cci32${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 32:   ${BLD}$title32a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title32b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title32c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity32${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity32, $controlid, $stigid32, $ruleid32, $cci32, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258201)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid33${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid33${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid33${NORMAL}"
echo -e "${NORMAL}CCI:       $cci33${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 33:   ${BLD}$title33a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title33b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title33c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity33${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity33, $controlid, $stigid33, $ruleid33, $cci33, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258202)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid34${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid34${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid34${NORMAL}"
echo -e "${NORMAL}CCI:       $cci34${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 34:   ${BLD}$title34a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title34b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title34c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity34${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity34, $controlid, $stigid34, $ruleid34, $cci34, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258203)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid35${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid35${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid35${NORMAL}"
echo -e "${NORMAL}CCI:       $cci35${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 35:   ${BLD}$title35a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title35b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title35c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity35${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity35, $controlid, $stigid35, $ruleid35, $cci35, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258204)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid36${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid36${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid36${NORMAL}"
echo -e "${NORMAL}CCI:       $cci36${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 36:   ${BLD}$title36a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title36b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title36c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity36${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity36, $controlid, $stigid36, $ruleid36, $cci36, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258205)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid37${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid37${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid37${NORMAL}"
echo -e "${NORMAL}CCI:       $cci37${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 37:   ${BLD}$title37a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title37b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title37c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity37${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity37, $controlid, $stigid37, $ruleid37, $cci37, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258206)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid38${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid38${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid38${NORMAL}"
echo -e "${NORMAL}CCI:       $cci38${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 38:   ${BLD}$title38a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title38b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title38c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity38${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity38, $controlid, $stigid38, $ruleid38, $cci38, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258207)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid39${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid39${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid39${NORMAL}"
echo -e "${NORMAL}CCI:       $cci39${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 39:   ${BLD}$title39a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title39b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title39c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity39${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity39, $controlid, $stigid39, $ruleid39, $cci39, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258208)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid40${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid40${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid40${NORMAL}"
echo -e "${NORMAL}CCI:       $cci40${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 40:   ${BLD}$title40a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title40b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title40c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity40${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity40, $controlid, $stigid40, $ruleid40, $cci40, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258209)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid41${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid41${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid41${NORMAL}"
echo -e "${NORMAL}CCI:       $cci41${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 41:   ${BLD}$title41a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title41b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title41c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity41${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity41, $controlid, $stigid41, $ruleid41, $cci41, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258210)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid42${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid42${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid42${NORMAL}"
echo -e "${NORMAL}CCI:       $cci42${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 42:   ${BLD}$title42a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title42b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title42c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity42${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity42, $controlid, $stigid42, $ruleid42, $cci42, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258215)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid43${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid43${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid43${NORMAL}"
echo -e "${NORMAL}CCI:       $cci43${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 43:   ${BLD}$title43a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title43b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title43c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity43${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity43, $controlid, $stigid43, $ruleid43, $cci43, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258216)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid44${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid44${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid44${NORMAL}"
echo -e "${NORMAL}CCI:       $cci44${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 44:   ${BLD}$title44a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title44b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title44c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity44${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity44, $controlid, $stigid44, $ruleid44, $cci44, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258217)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid45${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid45${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid45${NORMAL}"
echo -e "${NORMAL}CCI:       $cci45${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 45:   ${BLD}$title45a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title45b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title45c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity45${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity45, $controlid, $stigid45, $ruleid45, $cci45, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258218)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid46${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid46${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid46${NORMAL}"
echo -e "${NORMAL}CCI:       $cci46${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 46:   ${BLD}$title46a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title46b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title46c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity46${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity46, $controlid, $stigid46, $ruleid46, $cci46, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258219)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid47${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid47${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid47${NORMAL}"
echo -e "${NORMAL}CCI:       $cci47${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 47:   ${BLD}$title47a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title47b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title47c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity47${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity47, $controlid, $stigid47, $ruleid47, $cci47, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258220)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid48${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid48${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid48${NORMAL}"
echo -e "${NORMAL}CCI:       $cci48${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 48:   ${BLD}$title48a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title48b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title48c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity48${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity48, $controlid, $stigid48, $ruleid48, $cci48, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258221)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid49${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid49${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid49${NORMAL}"
echo -e "${NORMAL}CCI:       $cci49${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 49:   ${BLD}$title49a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title49b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title49c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity49${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity49, $controlid, $stigid49, $ruleid49, $cci49, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258222)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid50${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid50${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid50${NORMAL}"
echo -e "${NORMAL}CCI:       $cci50${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 50:   ${BLD}$title50a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title50b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title50c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity50${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity50, $controlid, $stigid50, $ruleid50, $cci50, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258223)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid51${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid51${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid51${NORMAL}"
echo -e "${NORMAL}CCI:       $cci51${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 51:   ${BLD}$title51a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title51b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title51c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity51${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity51, $controlid, $stigid51, $ruleid51, $cci51, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258224)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid52${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid52${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid52${NORMAL}"
echo -e "${NORMAL}CCI:       $cci52${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 52:   ${BLD}$title52a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title52b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title52c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity52${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity52, $controlid, $stigid52, $ruleid52, $cci52, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258225)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid53${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid53${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid53${NORMAL}"
echo -e "${NORMAL}CCI:       $cci53${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 53:   ${BLD}$title53a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title53b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title53c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity53${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity53, $controlid, $stigid53, $ruleid53, $cci53, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258234)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid54${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid54${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid54${NORMAL}"
echo -e "${NORMAL}CCI:       $cci54${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 54:   ${BLD}$title54a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title54b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title54c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity54${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity54, $controlid, $stigid54, $ruleid54, $cci54, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258236)${NORMAL}"

echo
echo -e "${BAR}-------------------------------------------------------------------${NORMAL}"
echo -e "${NORMAL}SCRIPT:    $prog${NORMAL}"
echo -e "${NORMAL}HOSTNAME:  $hostname running $os${NORMAL}"
echo -e "${NORMAL}STIG:      ${CYN}$stig${NORMAL}"
echo -e "${NORMAL}STIG ID:   $stigid55${NORMAL}"
echo -e "${NORMAL}RULE ID:   $ruleid55${NORMAL}"
echo -e "${NORMAL}VULN ID:   $vulnid55${NORMAL}"
echo -e "${NORMAL}CCI:       $cci55${NORMAL}"
echo -e "${NORMAL}CONTROL:   ${GRN}$controlid${NORMAL}"
echo -e "${NORMAL}TEST 55:   ${BLD}$title55a${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title55b${NORMAL}"
echo -e "${NORMAL}           ${BLD}$title55c${NORMAL}"
echo -e "${NORMAL}SEVERITY:  ${BLD}$severity55${NORMAL}"

datetime="$(date +%FT%H:%M:%S)"

echo -e "${NORMAL}$hostname, $severity55, $controlid, $stigid55, $ruleid55, $cci55, $datetime, ${CYN}VERIFY, (See AU-12 Audit Generation: V-258241)${NORMAL}"

exit
