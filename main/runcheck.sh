#! /bin/bash

########################################################
#  Changes:
#
#  20190220 - Modified to run 2018 and 2019 RHEL7 STIGs
#  20230314 - Modified to run 2023 RHEL7 STIGs
#  20240429 - Modified to run 2024 RHEL8 STIGs
#  20251018 - Modified to run 2025 RHEL9 STIGs
#
########################################################

#**************************************************
# check if the script is being run as root
 if [ "$EUID" -ne 0 ]
 then
    echo "Please run with sudo or as root"
    exit
 fi
#**************************************************

IFS='
'	 
hostname=$(uname -n | awk '{print $2}')

# variable declaration
filename=$(basename $0)
prog=$(basename $0 | sed 's/.sh$//')

# more variable declarations
passcnt=0
verifycnt=0			# tally of controls that need verification
cat1pass=0			# tally of CAT I controls that passed
cat2pass=0			# tally of CAT II controls that passed
cat3pass=0			# tally of CAT III controls that passed
cat1fail=0			# tally of CAT I controls that failed
cat2fail=0			# tally of CAT II controls that failed
cat3fail=0			# tally of CAT III controls that failed
totalcnt=0			# tally of total controls
passcnt=0			# tally of controls that passed
failcnt=0			# tally of controls that failed
testcnt=0			# tally of all tests
nacnt=0				# tally of controls that are not applicable


#***************************************************
# directory declarations
#
# This will parse out the directory where the script is located
# assuming that the script is located in "main" subdirectory under
# the base directory
base_dir=$(readlink -f $0 | sed "s/\\/main\/${filename}//")
#
#***************************************************

conf_dir=$base_dir/conf
main_dir=$base_dir/main
reports_dir=$base_dir/reports
scripts_dir=$base_dir/scripts
cst_rhel7_2023_dir=$scripts_dir/cst-rhel7/2023
cst_rhel8_2024_dir=$scripts_dir/cst-rhel8/2024
cst_rhel9_2025_dir=$scripts_dir/cst-rhel9/2025
tmp_dir=$base_dir/tmp

# file declarations
working_file=$tmp_dir/$prog.$$-$RANDOM.wrk
temp_file=$tmp_dir/$prog.$$-$RANDOM.tmp
status_file=$tmp_dir/$prog.$$-$RANDOM.stat
temp_report_file=$tmp_dir/ComplianceReport.$prog.$$-$RANDOM.tmp
report_file=$reports_dir/ComplianceReport._$(date +%F-%H%M).txt
brief_report_file=$reports_dir/cst-$(hostname)_$(date +%F-%H%M)-brief.txt
long_report_file=$reports_dir/cst-$(hostname)_$(date +%F-%H%M)-full.txt
csv_report_file=$reports_dir/cst-$(hostname)_$(date +%F-%H%M)-brief.csv
xml_report_file=$reports_dir/cst-$(hostname)_$(date +%F-%H%M)-xccdf.xml
score_report_file=$reports_dir/cst-$(hostname)_$(date +%F-%H%M)-score.txt
cst_rhel7_2023_cfg=$conf_dir/cst-rhel7_2023.cfg
cst_rhel8_2024_cfg=$conf_dir/cst-rhel8_2024.cfg
cst_rhel9_2025_cfg=$conf_dir/cst-rhel9_2025.cfg
exceptions=$conf_dir/exceptions.cfg

> $score_report_file

# Color declarations
RED=`echo    "\e[31;1m"`        # bold red
GRN=`echo    "\e[32;1m"`        # bold green
BLD=`echo    "\e[0;1m"`         # bold black
CYN=`echo    "\e[33;1;35m"`     # bold cyan
YLO=`echo    "\e[93;1m"`        # bold yellow
BAR=`echo    "\e[11;1;44m"`     # blue separator bar
NORMAL=`echo "\e[0m"`           # normal
MENU=`echo   "\e[30;1;1m"`      # bold black on light blue background
NUMBER=`echo "\e[32;1;48m"`     # light green

  clear
  echo -e "${BLD}******************************************${NORMAL}"
  echo -e "${BLD}* ${NUMBER} 1)${BLD} Compliance Self Test RHEL 7 (2023) ${BLD}*${NORMAL}"
  echo -e "${BLD}* ${NUMBER} 2)${BLD} Compliance Self Test RHEL 8 (2024) ${BLD}*${NORMAL}"
  echo -e "${BLD}* ${NUMBER} 3)${BLD} Compliance Self Test RHEL 9 (2025) ${BLD}*${NORMAL}"
  echo -e "${BLD}* ${NUMBER} 4)${BLD} Exit                               ${BLD}*${NORMAL}"
  echo -e "${BLD}******************************************${NORMAL}"
  echo
  echo -e "${BLD}Select a test ${YLO}or just hit Enter to quit.${NORMAL}"

  # Get the menu option selected
  read opt

  # Output the menu option selected
  fn_option_picked () {
    # menu item selected action
    echo $1
  }

  # Start working files with a clean slate
  fn_cleanup () {
    # remove temporary files
    [ -w $status_file ] && rm -f $status_file
    [ -w $temp_file ] && rm -f $temp_file
    [ -w $working_file ] && rm -f $working_file
    [ -w $temp_report_file ] && rm -f $temp_report_file
    exit $1
  }

  fn_scriptAvail () {
    cfgPath=$1

    # clear the contents of the working file's list of scripts to run. 
    > $working_file

    # place all scripts into the working file, excluding any that are commented out.
    grep -v "^#" $cfgPath > $working_file

    # if an exceptions file exists, omit scripts it contains from the working file
    if [ -f $exceptions ]
    then
      while read line
      do
        # delete any scripts that are included in the exceptions.cfg
        sed -i "/$line/d" $working_file
      done < $exceptions
    fi

    # sort the working files in ascending order and remove empty lines
    sed -i "/^$/d" $working_file
    sort -n $working_file -o $working_file 

  }

  makeReports () {
    # clear out the report files
    > $brief_report_file
    > $long_report_file
    > $csv_report_file
    > $xml_report_file

    # Pull the pass/fail test results in the results file and send them to the 'brief.txt' report
    cat $status_file | grep $(hostname) | \
       egrep -i '(ac-|at-|au-|ca-|cm-|cp-|ia-|ir-|ma-|mp-|pe-|pl-|ps-|ra-|sa-|sc-|si-|pm-)' | \
       grep -v 'HOSTNAME:' | grep -v 'RESULT:' > $brief_report_file

    # Copy the status file to the 'full.txt' file
    cp $status_file $long_report_file

    # Copy the 'brief.txt' file to the 'brief.csv' file
    cp $brief_report_file $csv_report_file

    # Insert a column header line in the 'brief.csv' file
    sed -i '1s/^/Hostname, CAT, Control Group, STIG ID, RULE ID, CCI, Datetime, Pass\/Fail, Result\n/' $csv_report_file

    # Count test results grouped by result status.
    testcnt="$(more $brief_report_file | wc -l)"
    verifycnt="$(grep VERIFY $brief_report_file | wc -l)"
    passcnt="$(grep PASSED $brief_report_file | wc -l)"
    failcnt="$(grep FAILED $brief_report_file | wc -l)"
    nacnt="$(grep N/A $brief_report_file | wc -l)"

    # Count test results grouped by result CAT status and pass/fail status.
    cat1pass="$(grep PASSED $brief_report_file | grep 'CAT I,' | wc -l)"
    cat1fail="$(grep FAILED $brief_report_file | grep 'CAT I,' | wc -l)"
    cat1na="$(grep 'N/A' $brief_report_file | grep 'CAT I,' | wc -l)"
    cat2pass="$(grep PASSED $brief_report_file | grep 'CAT II,' | wc -l)"
    cat2fail="$(grep FAILED $brief_report_file | grep 'CAT II,' | wc -l)"
    cat2na="$(grep 'N/A' $brief_report_file | grep 'CAT II,' | wc -l)"
    cat3pass="$(grep PASSED $brief_report_file | grep 'CAT III,' | wc -l)"
    cat3fail="$(grep FAILED $brief_report_file | grep 'CAT III,' | wc -l)"
    cat3na="$(grep 'N/A' $brief_report_file | grep 'CAT III,' | wc -l)"

    # initialize the array that lists each test that resulted in 'VERIFY'.

    lefttocheck=()

    # Pull out all the lines in the 'brief.txt' file that contain 'VERIFY'
    verifylist="$(grep VERIFY $brief_report_file)"

    # For each line in the 'verifylist' array, search the 'brief.txt' file for results with the 
    # same rule ID to see if it either passed or failed. If found, increment the counts of the
    # passed or failed counters, and decrement the verify counter accordingly. This was done to
    # avoid running the same script multiple times for vulnerabilities that call out the same
    # test.

    if [[ $verifylist ]]
    then
       for line in ${verifylist[@]}
       do
          cat="$(echo $line | awk -F, '{print $2}' | sed 's/^[ ]*//')"
          grp="$(echo $line | awk -F, '{print $3}' | sed 's/^[ ]*//')"
          rule="$(echo $line | awk -F, '{print $5}' | sed 's/^[ ]*//')"                                      
          stat="$(grep $rule $brief_report_file | grep -v 'VERIFY' | awk -F, '{print $8}')"

	  if [[ $stat =~ 'PASSED' ]]
          then
             (( passcnt++ ))
             (( verifycnt-- ))
             case $cat in
                'CAT I')
                    (( cat1pass++ ))
                    ;;
                'CAT II')
                    (( cat2pass++ ))
                    ;;
                'CAT III')
                    (( cat3pass++ ))
                    ;;
             esac
          elif [[ $stat =~ 'FAILED' ]]
          then
             (( failcnt++ ))
             (( verifycnt-- ))
             case $cat in
                'CAT I')
                    (( cat1fail++ ))
                    ;;
                'CAT II')
                    (( cat2fail++ ))
                    ;;
                'CAT III')
                    (( cat3fail++))
                    ;;
             esac
          fi
   
          if ! [[ $stat ]]
          then
             # Append this array with any test marked 'VERIFY' that didn't find another test with 
             # a matching vulnerability ID that either passed or failed.
             lefttocheck+=("$rule $grp")
          fi
       done
    fi

    # Output report column headers and results to the console
    echo
    printf "%-10s%10s%10s%10s%10s\n" " " "CAT I" "CAT II" "CAT III"

    # Output report pass/fail counts to the console
    echo "--------------------------------------------------"
    printf "%-10s%10s%10s%10s%10s\n" "PASSED" "$cat1pass" "$cat2pass" "$cat3pass"
    echo "--------------------------------------------------"
    printf "%-10s%10s%10s%10s%10s\n" "FAILED" "$cat1fail" "$cat2fail" "$cat3fail"
    echo "--------------------------------------------------"
    printf "%-10s%10s%10s%10s%10s\n" "N/A"    "$cat1na"   "$cat2na"   "$cat3na"
    echo "--------------------------------------------------"

    # Output report column headers and results to the 'score.txt' file
    echo >> $score_report_file
    printf "%-10s%10s%10s%10s%10s\n" " " "CAT I" "CAT II" "CAT III" >> $score_report_file

    # Output report pass/fail counts to the 'score.txt' file
    echo "--------------------------------------------------" >> $score_report_file
    printf "%-10s%10s%10s%10s%10s\n" "PASSED" "$cat1pass" "$cat2pass" "$cat3pass" >> $score_report_file
    echo "--------------------------------------------------" >> $score_report_file
    printf "%-10s%10s%10s%10s%10s\n" "FAILED" "$cat1fail" "$cat2fail" "$cat3fail" >> $score_report_file
    echo "--------------------------------------------------" >> $score_report_file
    printf "%-10s%10s%10s%10s%10s\n" "N/A"    "$cat1na"   "$cat2na"   "$cat3na" >> $score_report_file
    echo "--------------------------------------------------" >> $score_report_file

    # Output vulnerabilities that need further assessment to the console.
    echo
    echo -e "${NORMAL}Vulnerabilities left to verify--------------------${NORMAL}"
    for v in ${lefttocheck[@]}
    do
       echo $v
    done | sort 
    echo

    # Output vulnerabilities that need further assessment to the 'score.txt' file
    echo >> $score_report_file
    echo "Vulnerabilities left to verify--------------------" >> $score_report_file
    for v in ${lefttocheck[@]}
    do
       echo $v >> $score_report_file
    done | sort >> $score_report_file
    echo >> $score_report_file

    totalcnt=$((testcnt - verifycnt - nacnt))
    failcnt=$((failcnt + ofailcnt))
    passcnt=$((passcnt + opasscnt))

    calc(){ awk "BEGIN { print "$*" }"; }

    let "fail = $failcnt"
    let "pass = $passcnt"
    let "total = $totalcnt"
    let "na = $nacnt"

    echo -e "${NORMAL}Calculating score with ($pass / $total * 100)"
    echo "Calculating score with ($pass / $total * 100)" >> $score_report_file

    score=`calc $pass/$total*100`
    score="$(echo $score | awk -F. '{print $1}')"

    echo "--------------------------------------------------"
    echo -e "${NORMAL}TOTAL:    $testcnt tests.${NORMAL}"
    echo -e "${NORMAL}PASSED:   $passcnt tests passed.${NORMAL}"
    echo -e "${NORMAL}FAILED:   $failcnt tests failed.${NORMAL}"
    echo -e "${NORMAL}N/A:      $nacnt tests not applicable.${NORMAL}"
    echo -e "${NORMAL}VERIFY:   $verifycnt tests left to verify.${NORMAL}"

    echo "--------------------------------------------------" >> $score_report_file
    echo "TOTAL:    $testcnt tests." >> $score_report_file
    echo "PASSED:   $passcnt tests passed." >> $score_report_file
    echo "FAILED:   $failcnt tests failed." >> $score_report_file
    echo "N/A:      $nacnt tests not applicable." >> $score_report_file
    echo "VERIFY:   $verifycnt tests left to verify." >> $score_report_file

    if [[ $score ]]
    then
       if (( $score < 80 ))
       then
          echo -e "${NORMAL}SCORE:    ${RED}$score${NORMAL}"
          echo "SCORE:    $score$" >> $score_report_file
       elif (( $score >= 80 && $score < 90 ))
       then
          echo -e "${NORMAL}SCORE:    ${YLO}$score${NORMAL}"
          echo "SCORE:    $score" >> $score_report_file
       else
          echo -e "${NORMAL}SCORE:    ${GRN}$score${NORMAL}"
          echo "SCORE:    $score" >> $score_report_file
       fi
    fi
    echo "--------------------------------------------------"
    echo "--------------------------------------------------" >> $score_report_file

    # remove colors from the csv file
    sed -i 's/[[:cntrl:]]\[0m//g' $csv_report_file
    sed -i 's/[[:cntrl:]]\[31\;1m//g' $csv_report_file
    sed -i 's/[[:cntrl:]]\[32\;1m//g' $csv_report_file
    sed -i 's/[[:cntrl:]]\[0\;1m//g' $csv_report_file
    sed -i 's/[[:cntrl:]]\[33\;1\;35m//g' $csv_report_file
    sed -i 's/[[:cntrl:]]\[93\;1m//g' $csv_report_file
    sed -i 's/[[:cntrl:]]\[11\;1\;44m//g' $csv_report_file

    # Comment the next line out if you want to preserve the working files. This might
    # be helpful if you need to review the output for signs of errors.

    rm -rf $tmp_dir/*

    echo
    echo "Full report:  $long_report_file"
    echo "Brief report: $brief_report_file"
    echo "Score report: $score_report_file"
    echo "Excel report: $csv_report_file"
    echo "XCCDF report: $xml_report_file"
    echo

    echo >> $score_report_file
    echo "Full report:  $long_report_file" >> $score_report_file
    echo "Brief report: $brief_report_file" >> $score_report_file
    echo "Score report: $score_report_file" >> $score_report_file
    echo "Excel report: $csv_report_file" >> $score_report_file
    echo "XCCDF report: $xml_report_file" >> $score_report_file
    echo >> $score_report_file

  }

  runScripts () {
    starttimestamp="$(date +%FT%H:%M:%S)"
    > $status_file

    echo "CST Scripts ------------------" >> $score_report_file

    while read runScript
    do
       if [ -x $scriptPath/$runScript ]
       then
          echo "$runScript"
          echo "$runScript" >> $score_report_file

          # run the target script and capture the output
          > $temp_file
          /bin/bash $scriptPath/$runScript &> $temp_file
          output=$(cat $temp_file)

          echo "$output" >> $status_file

       else
          echo "$runScript is not executable"
          echo "$runScript is not executable" >> $score_report_file
       fi
    done < $working_file
    endtimestamp="$(date +%FT%H:%M:%S)"
  }

  makeXccdf () {

  score="$(grep 'SCORE:' $score_report_file | awk '{print $2}' | sed -e 's/^[[:space:]]*//' | sed 's/^[^m]*m//' | sed -r 's/[[:cntrl:]].*$//' )" 

  echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" >> $xml_report_file
  echo "<Benchmark xmlns=\"http://checklists.nist.gov/xccdf/1.1\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" id=\"Red_Hat_Enterprise_Linux_STIG\" resolved=\"1\" xml:lang=\"en\" style=\"SCAP_1.1\">" >> $xml_report_file
  echo "  <status date=\"2016-04-22\">accepted</status>" >> $xml_report_file
  echo "  <title xmlns:xhtml=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\">Red_Hat_Enterprise_Linux_9_STIG</title>" >> $xml_report_file
  echo "  <notice xmlns:xhtml=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\" id=\"terms-of-use\"/>" >> $xml_report_file
  echo "  <reference xmlns:dc=\"http://purl.org/dc/elements/1.1/\" href=\"http://iase.disa.mil\">" >> $xml_report_file
  echo "    <dc:publisher>DISA</dc:publisher>" >> $xml_report_file
  echo "    <dc:source>STIG.DOD.MIL</dc:source>" >> $xml_report_file
  echo "  </reference>" >> $xml_report_file
  echo "  <plain-text id=\"release-info\">Release: 5 Benchmark Date: 02 Jul 2025</plain-text>" >> $xml_report_file
  echo "  <platform idref=\"cpe:/o:redhat:enterprise_linux:9\"/>" >> $xml_report_file
  echo "  <version>1</version>" >> $xml_report_file
  echo "  <metadata xmlns:xhtml=\"http://www.w3.org/1999/xhtml\">" >> $xml_report_file
  echo "    <dc:creator xmlns:dc=\"http://purl.org/dc/elements/1.1/\">DISA</dc:creator>" >> $xml_report_file
  echo "    <dc:publisher xmlns:dc=\"http://purl.org/dc/elements/1.1/\">DISA</dc:publisher>" >> $xml_report_file
  echo "    <dc:contributor xmlns:dc=\"http://purl.org/dc/elements/1.1/\">DISA</dc:contributor>" >> $xml_report_file
  echo "    <dc:source xmlns:dc=\"http://purl.org/dc/elements/1.1/\">STIG.DOD.MIL</dc:source>" >> $xml_report_file
  echo "  </metadata>" >> $xml_report_file
  echo "  <model system=\"urn:xccdf:scoring:default\"/>" >> $xml_report_file
  echo "  <TestResult id=\"xccdf_org.open-scap_testresult_default-profile\" start-time=\"$starttimestamp\" end-time=\"$endtimestamp\" version=\"1\">" >> $xml_report_file
  echo "    <benchmark href=\"U_Red_Hat_Enterprise_Linux_9_STIG_V2R5_Manual-xccdf\"/>" >> $xml_report_file
  echo "    <title>Compliance Self-Test (CST) Scan Result</title>" >> $xml_report_file
  echo "    <target>rhel9</target>" >> $xml_report_file
  echo "    <platform idref=\"cpe:/o:redhat:enterprise_linux:9\"/>" >> $xml_report_file

  while IFS= read -r line; do
    if ! [[ $line =~ "RULE ID" || $line =~ "See " ]]
    then
      echo "$line" | awk -F', ' '{print "          <rule-result idref=\""$5"\" time=\""$7"\" weight=\"10\">"}' >> $xml_report_file
      echo "$line" | awk -F', ' '{print "            <result>"$8"</result>"}' >> $xml_report_file
      echo "          </rule-result>" >> $xml_report_file
    fi
  done < "$1"
  sed -i 's/idref=\" SV/idref=\"SV/g' $xml_report_file
  sed -i 's/rule \"/rule\"/g' $xml_report_file
  sed -i 's/result> /result>/g' $xml_report_file
  sed -i 's/PASSED/pass/g' $xml_report_file
  sed -i 's/FAILED/fail/g' $xml_report_file
  sed -i 's/N\/A/notapplicable/g' $xml_report_file
  sed -i 's/VERIFY/verify/g' $xml_report_file
  echo "    <score system=\"urn:xccdf:scoring:default\" maximum=\"100\">\"$score\"</score>" >> $xml_report_file
  echo "  </TestResult>" >> $xml_report_file
  echo "</Benchmark>" >> $xml_report_file
  }

  # Make sure only root can modify or delete the report files
  setperms () {
    reports="$(grep $(hostname) $score_report_file | awk -F ': ' '{print $2}' | sed 's/^ *//')"
    if [[ $reports ]]
    then
      for file in ${reports[@]}
      do
        chmod 640 $file
      done
    fi
  }

  if [[ $opt == "" ]]
  then
     exit 0
  else
     scriptPath=null

     case $opt in
        1)
           fn_option_picked "Compliance Self Test for RHEL 7 (2023)"
           fn_scriptAvail "$cst_rhel7_2023_cfg"
           scriptPath=$cst_rhel7_2023_dir
           choice="Compliance Self Test for RHEL 7 (2023)"
           ;;
        2)
           fn_option_picked "Compliance Self Test for RHEL 8 (2024)"
           fn_scriptAvail "$cst_rhel8_2024_cfg"
           scriptPath=$cst_rhel8_2024_dir
           choice="Compliance Self Test for RHEL 8 (2024)"
           ;;
        3)
           fn_option_picked "Compliance Self Test for RHEL 9 (2025)"
           fn_scriptAvail "$cst_rhel9_2025_cfg"
           scriptPath=$cst_rhel9_2025_dir
           choice="Compliance Self Test for RHEL 9 (2025)"
           ;;
        4)
           fn_option_picked "Exit"
           exit 0
           ;;
        *)
           exit 0
           ;;
     esac
  fi

  echo "$(hostname)" > $score_report_file
  echo "$(date +%FT%H:%M:%S)" >> $score_report_file
  echo $choice >> $score_report_file
  runScripts $working_file
  makeReports $status_file
  makeXccdf $csv_report_file
  #setperms #Uncomment if $base_dir is on the local (virtual) host, not a physical host share.

exit 0
