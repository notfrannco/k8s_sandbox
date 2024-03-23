#!/bin/bash

ARF_FILE=$1 # ansible with set this name with the profile name of the oscap
HOSTNAME=$(grep "<target>" $ARF_FILE | grep -oPm1 "(?<=<target>)[^<]+")
SCAP_PROFILE=$(basename -s .xml $ARF_FILE)
TIMESTAMP=$(sed -nr '/start-time=/{s/.*start-time="([^"]+)".*/\1/;p;}' $ARF_FILE  | sed 's/[-T:]//g' | awk '{print substr($0, 1, 12)}')
REPORT_NAME=$SCAP_PROFILE"_"$TIMESTAMP.html

echo "ARF_FILE: " $ARF_FILE
echo "hostname: " $HOSTNAME
echo "scap_profile: " $SCAP_PROFILE
echo "scap_profile_comple: " $SCAP_PROFILE"_"$HOSTNAME"_"$TIMESTAMP
echo "report_name: " $REPORT_NAME

# set correct time stamp for the golang parser
sed -i 's/time=".................../&-00:00/g' $ARF_FILE

# generate a report
oscap xccdf generate report --output $REPORT_NAME $ARF_FILE
