#! /bin/bash

# Used to extract the list of unique CCIs identified in the STIG text files.

# Usage: # ./getcci.sh RHEL-9-v2-r5-AU23.txt

list="$(grep CCI $1 | sort | uniq)"

# Check that the CCI list was created
if [[ $list ]]
then
  # Create an array of CCIs from the list of CCIs
  while IFS= read -r line
  do
    ccilist+=("$line")
  done <<< "$list"
else
  echo Nothing returned
  exit
fi

# Using the array element position, collect the associated CCI requirement,
# capturing only the last instance of multiple copies.
pos=0
prev=0
for line in ${ccilist[@]}
do
  cci="$(echo ${ccilist[pos]})"
  if ! [[ $prev == $cci ]]
  then
    text=$(sed -n "/$cci/, /NIST/{ /NIST/!p }" $1)
    firstword="$(echo $text | awk '{print $1}')"
    requirement=${text##*$firstword}
    echo $cci
    echo $requirement
    echo

    prev=$cci
    (( pos++ ))
  fi
done

exit
